import { useEffect, useRef, useState, type FormEvent } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { listen } from "@tauri-apps/api/event";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Check,
  CheckCircle2,
  Clipboard,
  FileKey2,
  FolderOpen,
  KeyRound,
  ListTree,
  LoaderCircle,
  LockKeyhole,
  Plus,
  Pencil,
  RefreshCw,
  RotateCcw,
  Save,
  Search,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  SquareTerminal,
  Terminal,
  Trash2,
  X,
  XCircle,
  Zap,
} from "lucide-react";

type AuthKind = "password" | "private_key";

type InstanceSummary = {
  instance_id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  auth_kind: AuthKind;
  host_key_check: boolean;
  notes: string | null;
  has_secret: boolean;
  created_at: string;
  updated_at: string;
};

type InstanceDraft = {
  instance_id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  auth_kind: AuthKind;
  host_key_check: boolean;
  notes: string;
  password: string;
  private_key: string;
  private_key_path: string;
  passphrase: string;
  keep_existing_secret: boolean;
  has_saved_secret: boolean;
};

type TestConnectionResult = {
  success: boolean;
  message: string;
};

type McpConfigBundle = {
  command: string;
  args: string[];
  stdio_json: string;
  helper_found: boolean;
  helper_warning: string | null;
};

type OperationLogEntry = {
  id: number;
  client_id: string;
  client_session_id: string;
  session_id: string;
  instance_id: string;
  operation: string;
  details: string;
  created_at: string;
};

type AppSettings = {
  approval_level: ApprovalLevel;
  auto_review: {
    base_url: string;
    model: string;
  };
  api_key_configured: boolean;
};

type ApprovalLevel = "system_dialog" | "app_dialog" | "allow_all" | "auto_agent";

type RuleType = "tool" | "command" | "path" | "instance";

type RuleAction = "allow" | "deny" | "require_approval";

type WhitelistRule = {
  id: number;
  rule_type: RuleType;
  pattern: string;
  action: RuleAction;
  enabled: boolean;
  is_builtin: boolean;
  created_at: string;
};

type WhitelistRuleInput = {
  rule_type: RuleType;
  pattern: string;
  action: RuleAction;
};

type ParsedTarget = {
  host: string;
  port: number;
  username: string;
};

const runningInTauri = isTauri();
const appWindow = runningInTauri ? getCurrentWindow() : null;

const emptyDraft = (): InstanceDraft => ({
  instance_id: "",
  name: "",
  host: "",
  port: 22,
  username: "",
  auth_kind: "password",
  host_key_check: false,
  notes: "",
  password: "",
  private_key: "",
  private_key_path: "",
  passphrase: "",
  keep_existing_secret: false,
  has_saved_secret: false,
});

function fromSummary(instance: InstanceSummary): InstanceDraft {
  return {
    instance_id: instance.instance_id,
    name: instance.name,
    host: instance.host,
    port: instance.port,
    username: instance.username,
    auth_kind: instance.auth_kind,
    host_key_check: instance.host_key_check,
    notes: instance.notes ?? "",
    password: "",
    private_key: "",
    private_key_path: "",
    passphrase: "",
    keep_existing_secret: instance.has_secret,
    has_saved_secret: instance.has_secret,
  };
}

function hasInlineCredential(draft: InstanceDraft): boolean {
  return Boolean(
    draft.password.trim()
    || draft.private_key.trim()
    || draft.private_key_path.trim()
    || draft.passphrase.trim(),
  );
}

export default function App() {
  const [instances, setInstances] = useState<InstanceSummary[]>([]);
  const [draft, setDraft] = useState<InstanceDraft>(emptyDraft());
  const [targetInput, setTargetInput] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isCreating, setIsCreating] = useState(true);
  const [configs, setConfigs] = useState<McpConfigBundle | null>(null);
  const [showConfigDialog, setShowConfigDialog] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [instanceQuery, setInstanceQuery] = useState("");
  const [status, setStatus] = useState<string>("正在加载连接...");
  const [statusTone, setStatusTone] = useState<"neutral" | "success" | "danger">(
    "neutral",
  );
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState<"config" | "logs">("config");
  const [logs, setLogs] = useState<OperationLogEntry[]>([]);
  const [loadingLogs, setLoadingLogs] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [expandedStdout, setExpandedStdout] = useState<0 | 10 | 20>(0);
  const [lastLogId, setLastLogId] = useState(0);
  const [showSettings, setShowSettings] = useState(false);
  const [appSettings, setAppSettings] = useState<AppSettings | null>(null);
  const [whitelistRules, setWhitelistRules] = useState<WhitelistRule[]>([]);
  const [loadingWhitelistRules, setLoadingWhitelistRules] = useState(false);
  const [savingSettings, setSavingSettings] = useState(false);
  const [restartingMcp, setRestartingMcp] = useState(false);
  const [restartResult, setRestartResult] = useState<{ kind: "success" | "error"; message: string } | null>(null);
  const logListRef = useRef<HTMLDivElement>(null);
  const activeTabRef = useRef(activeTab);
  const autoRefreshRef = useRef(autoRefresh);
  const lastLogIdRef = useRef(0);

  useEffect(() => {
    void loadData();
  }, []);

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      if (showDeleteDialog) {
        setShowDeleteDialog(false);
      } else if (showConfigDialog) {
        setShowConfigDialog(false);
      } else if (showSettings) {
        closeSettings();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [showConfigDialog, showDeleteDialog, showSettings]);

  async function hydrateDraft(instance: InstanceSummary) {
    const baseDraft = fromSummary(instance);
    if (instance.auth_kind !== "private_key") {
      setDraft(baseDraft);
      return;
    }

    try {
      const privateKeyPath = await invoke<string | null>("get_private_key_path", {
        instanceId: instance.instance_id,
      });
      setDraft({
        ...baseDraft,
        private_key_path: privateKeyPath ?? "",
      });
    } catch {
      setDraft(baseDraft);
    }
  }

  async function loadData() {
    try {
      const [loadedInstances, loadedConfigs] = await Promise.all([
        invoke<InstanceSummary[]>("list_instances"),
        invoke<McpConfigBundle>("get_mcp_configs"),
      ]);

      setInstances(loadedInstances);
      setConfigs(loadedConfigs);

      if (selectedId) {
        const selected = loadedInstances.find((item) => item.instance_id === selectedId);
        if (selected) {
          await hydrateDraft(selected);
          setTargetInput(formatTarget(selected.username, selected.host, selected.port));
          setIsCreating(false);
          return;
        }
      }

      if (loadedInstances.length > 0) {
        const first = loadedInstances[0];
        setSelectedId(first.instance_id);
        await hydrateDraft(first);
        setTargetInput(formatTarget(
          first.username,
          first.host,
          first.port,
        ));
        setIsCreating(false);
      } else {
        startCreateMode();
      }
      setStatus("已就绪。");
      setStatusTone("neutral");
    } catch (error) {
      if (!runningInTauri) {
        startCreateMode();
        setStatus("浏览器预览模式");
        setStatusTone("neutral");
        return;
      }
      setStatus(asMessage(error));
      setStatusTone("danger");
    }
  }

  useEffect(() => {
    if (activeTab === "logs") {
      void loadLogs();
    }
  }, [activeTab]);

  useEffect(() => {
    activeTabRef.current = activeTab;
  }, [activeTab]);

  useEffect(() => {
    autoRefreshRef.current = autoRefresh;
  }, [autoRefresh]);

  useEffect(() => {
    if (!runningInTauri) {
      return;
    }

    const setup = async () => {
      const unlisten = await listen("log-updated", () => {
        if (activeTabRef.current === "logs" && autoRefreshRef.current) {
          setTimeout(() => void loadNewLogs(), 150);
        }
      });
      return unlisten;
    };
    let unlisten: (() => void) | undefined;
    setup().then((fn) => { unlisten = fn; });
    return () => { unlisten?.(); };
  }, []);

  async function loadLogs() {
    setLoadingLogs(true);
    try {
      const entries = await invoke<OperationLogEntry[]>("get_operation_logs", { limit: 200 });
      const sorted = [...entries].reverse();
      setLogs(sorted);
      const latestId = sorted.length > 0 ? sorted[sorted.length - 1].id : 0;
      lastLogIdRef.current = latestId;
      setLastLogId(latestId);
    } catch (error) {
      setStatus(asMessage(error));
      setStatusTone("danger");
    } finally {
      setLoadingLogs(false);
    }
  }

  async function loadNewLogs() {
    const sinceId = lastLogIdRef.current;
    if (sinceId === 0) {
      void loadLogs();
      return;
    }
    try {
      const entries = await invoke<OperationLogEntry[]>("get_operation_logs_since", {
        sinceId,
        limit: 200,
      });
      if (entries.length === 0) return;
      setLogs((prev) => {
        const existingIds = new Set(prev.map((e) => e.id));
        const newEntries = entries.filter((e) => !existingIds.has(e.id));
        return [...prev, ...newEntries];
      });
      const maxId = entries.reduce((max, e) => Math.max(max, e.id), sinceId);
      lastLogIdRef.current = maxId;
      setLastLogId(maxId);
    } catch {
      // ignore background refresh failures
    }
  }

  useEffect(() => {
    if (logListRef.current) {
      logListRef.current.scrollTop = logListRef.current.scrollHeight;
    }
  }, [logs]);

  function startCreateMode() {
    setSelectedId(null);
    setDraft(emptyDraft());
    setTargetInput("");
    setIsCreating(true);
    setActiveTab("config");
    setShowSettings(false);
  }

  function selectInstance(instance: InstanceSummary) {
    setSelectedId(instance.instance_id);
    void hydrateDraft(instance);
    setTargetInput(formatTarget(instance.username, instance.host, instance.port));
    setIsCreating(false);
    setActiveTab("config");
    setShowSettings(false);
    setStatus(`正在编辑 ${instance.name}。`);
    setStatusTone("neutral");
  }

  async function handleSave() {
    if (draft.auth_kind === "private_key" && draft.private_key && draft.private_key_path) {
      setStatus("私钥内容和私钥文件路径不能同时填写。请二选一。");
      setStatusTone("danger");
      return;
    }
    if (!isCreating && !draft.keep_existing_secret && !hasInlineCredential(draft)) {
      setStatus("当前没有可保留的凭据，请输入密码或选择私钥后再保存。");
      setStatusTone("danger");
      return;
    }
    setSaving(true);
    try {
      const { has_saved_secret: _, ...draftForSave } = draft;
      const saved = await invoke<InstanceSummary>("save_instance", { draft: draftForSave });
      setInstances((current) => {
        const index = current.findIndex((instance) => instance.instance_id === saved.instance_id);
        if (index < 0) {
          return [...current, saved];
        }
        return current.map((instance) =>
          instance.instance_id === saved.instance_id ? saved : instance,
        );
      });
      setSelectedId(saved.instance_id);
      setDraft({
        ...fromSummary(saved),
        private_key_path: draft.private_key_path,
      });
      setTargetInput(formatTarget(saved.username, saved.host, saved.port));
      setIsCreating(false);
      setStatus(`已保存 ${saved.name}。`);
      setStatusTone("success");
    } catch (error) {
      setStatus(asMessage(error));
      setStatusTone("danger");
    } finally {
      setSaving(false);
    }
  }

  async function handleTest() {
    if (draft.auth_kind === "private_key" && draft.private_key && draft.private_key_path) {
      setStatus("私钥内容和私钥文件路径不能同时填写。请二选一。");
      setStatusTone("danger");
      return;
    }
    setTesting(true);
    try {
      const result = await invoke<TestConnectionResult>("test_connection", { draft });
      setStatus(result.message);
      setStatusTone(result.success ? "success" : "danger");
    } catch (error) {
      setStatus(asMessage(error));
      setStatusTone("danger");
    } finally {
      setTesting(false);
    }
  }

  async function handleDelete() {
    if (!selectedId) {
      return;
    }

    try {
      await invoke("delete_instance", { instanceId: selectedId });
      setShowDeleteDialog(false);
      startCreateMode();
      await loadData();
      setStatus(`已删除 ${selectedId}。`);
      setStatusTone("success");
    } catch (error) {
      setStatus(asMessage(error));
      setStatusTone("danger");
    }
  }

  async function loadSettings() {
    setLoadingWhitelistRules(true);
    try {
      const [settings, rules] = await Promise.all([
        invoke<AppSettings>("get_settings"),
        invoke<WhitelistRule[]>("list_whitelist_rules"),
      ]);
      setAppSettings(settings);
      setWhitelistRules(rules);
    } catch {
      // ignore loading failure
    } finally {
      setLoadingWhitelistRules(false);
    }
  }

  async function handleChangeApprovalLevel(approvalLevel: ApprovalLevel) {
    if (!appSettings) {
      return;
    }
    setSavingSettings(true);
    const newSettings: AppSettings = {
      ...appSettings,
      approval_level: approvalLevel,
    };
    try {
      const saved = await invoke<AppSettings>("save_settings", {
        request: {
          settings: newSettings,
          api_key: null,
          clear_api_key: false,
        },
      });
      setAppSettings(saved);
      setStatus("审核等级已更新。");
      setStatusTone("success");
    } catch (error) {
      setStatus(asMessage(error));
      setStatusTone("danger");
    } finally {
      setSavingSettings(false);
    }
  }

  async function handleSaveAutoReviewSettings(
    autoReview: { base_url: string; model: string },
    apiKey: string,
    clearApiKey: boolean,
  ) {
    if (!appSettings) {
      return;
    }
    setSavingSettings(true);
    try {
      const saved = await invoke<AppSettings>("save_settings", {
        request: {
          settings: {
            ...appSettings,
            auto_review: autoReview,
          },
          api_key: apiKey.trim() || null,
          clear_api_key: clearApiKey,
        },
      });
      setAppSettings(saved);
      setStatus("大模型审核配置已保存。");
      setStatusTone("success");
    } catch (error) {
      setStatus(asMessage(error));
      setStatusTone("danger");
      throw error;
    } finally {
      setSavingSettings(false);
    }
  }

  async function handleSaveWhitelistRule(
    id: number | null,
    input: WhitelistRuleInput,
  ) {
    setSavingSettings(true);
    try {
      if (id === null) {
        await invoke("add_whitelist_rule", {
          ruleType: input.rule_type,
          pattern: input.pattern,
          action: input.action,
        });
      } else {
        await invoke("update_whitelist_rule", {
          id,
          ruleType: input.rule_type,
          pattern: input.pattern,
          action: input.action,
        });
      }
      await loadSettings();
      setStatus(id === null ? "规则已添加。" : "规则已更新。重新匹配时立即生效。");
      setStatusTone("success");
    } catch (error) {
      setStatus(asMessage(error));
      setStatusTone("danger");
      throw error;
    } finally {
      setSavingSettings(false);
    }
  }

  async function handleToggleWhitelistRule(id: number, enabled: boolean) {
    setSavingSettings(true);
    try {
      await invoke("set_whitelist_rule_enabled", { id, enabled });
      await loadSettings();
      setStatus(enabled ? "规则已启用。" : "规则已停用。重新匹配时立即生效。");
      setStatusTone("success");
    } catch (error) {
      setStatus(asMessage(error));
      setStatusTone("danger");
    } finally {
      setSavingSettings(false);
    }
  }

  async function handleRemoveWhitelistRule(id: number) {
    setSavingSettings(true);
    try {
      await invoke("remove_whitelist_rule", { id });
      await loadSettings();
      setStatus("规则已删除。重新匹配时立即生效。");
      setStatusTone("success");
    } catch (error) {
      setStatus(asMessage(error));
      setStatusTone("danger");
    } finally {
      setSavingSettings(false);
    }
  }

  async function handleRestartMcp() {
    setRestartingMcp(true);
    setRestartResult(null);
    // 确保 loading 状态至少显示 1 秒，让用户能看见转圈
    const minDelay = new Promise<void>((resolve) => setTimeout(resolve, 1000));
    try {
      const [msg] = await Promise.all([invoke<string>("restart_mcp"), minDelay]);
      setRestartResult({ kind: "success", message: msg });
      setStatus(msg);
      setStatusTone("success");
    } catch (error) {
      const errMsg = asMessage(error);
      setRestartResult({ kind: "error", message: errMsg });
      setStatus(errMsg);
      setStatusTone("danger");
    } finally {
      setRestartingMcp(false);
      setTimeout(() => setRestartResult(null), 3000);
    }
  }

  function openSettings() {
    setShowSettings(true);
    void loadSettings();
  }

  function closeSettings() {
    setShowSettings(false);
  }

  async function copyConfig(label: string, content: string) {
    try {
      await writeText(content);
      setStatus(`已复制 ${label} MCP 配置。`);
      setStatusTone("success");
    } catch (error) {
      setStatus(asMessage(error));
      setStatusTone("danger");
    }
  }

  const requiresPassword = draft.auth_kind === "password";
  const requiresKey = draft.auth_kind === "private_key";
  const hasPrivateKeyConflict =
    requiresKey && draft.private_key.length > 0 && draft.private_key_path.length > 0;
  const selectedInstance = instances.find((instance) => instance.instance_id === selectedId);
  const canUseSavedCredential = Boolean(
    !isCreating
    && draft.keep_existing_secret
    && draft.has_saved_secret
    && selectedInstance?.auth_kind === draft.auth_kind,
  );
  const hasCredential = requiresPassword
    ? Boolean(draft.password.trim()) || canUseSavedCredential
    : Boolean(draft.private_key.trim() || draft.private_key_path.trim()) || canUseSavedCredential;
  const hasRequiredMetadata = Boolean(
    draft.instance_id.trim()
    && draft.name.trim()
    && draft.host.trim()
    && draft.username.trim()
    && draft.port > 0,
  );
  const canSubmit = hasRequiredMetadata && hasCredential && !hasPrivateKeyConflict;
  const normalizedQuery = instanceQuery.trim().toLocaleLowerCase();
  const filteredInstances = normalizedQuery
    ? instances.filter((instance) =>
      [instance.name, instance.instance_id, instance.host, instance.username]
        .some((value) => value.toLocaleLowerCase().includes(normalizedQuery)))
    : instances;

  async function handlePickPrivateKeyFile() {
    try {
      const selectedPath = await invoke<string | null>("pick_private_key_file");
      if (!selectedPath) {
        return;
      }
      setDraft((current) => ({
        ...current,
        private_key_path: selectedPath,
      }));
      setStatus("已选择私钥文件。");
      setStatusTone("success");
    } catch (error) {
      setStatus(asMessage(error));
      setStatusTone("danger");
    }
  }

  function applyTargetInput() {
    const parsed = parseSshTarget(targetInput);
    if (!parsed) {
      setStatus("无法识别 SSH 目标格式。请使用 ssh://user@host:22 或 user@host:22。");
      setStatusTone("danger");
      return;
    }

    setDraft((current) => ({
      ...current,
      host: parsed.host,
      port: parsed.port,
      username: parsed.username || current.username,
    }));
    setStatus("已解析 SSH 目标并填入主机 / 端口 / 用户名。");
    setStatusTone("success");
  }

  async function handleDragMouseDown(event: React.MouseEvent<HTMLElement>) {
    if (!appWindow) {
      return;
    }
    if (event.button !== 0) {
      return;
    }
    if (event.target !== event.currentTarget) {
      return;
    }

    try {
      await appWindow.startDragging();
    } catch {
      // ignore
    }
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="sidebar-top" onMouseDown={(event) => void handleDragMouseDown(event)}>
          <div className="brand">
            <div className="brand-mark" aria-hidden="true">
              <SquareTerminal size={20} strokeWidth={1.8} />
            </div>
            <div className="brand-copy">
              <h1>Xiic SSH</h1>
              <p>连接管理器</p>
            </div>
          </div>
        </div>

        <button className="primary-button sidebar-create-button" onClick={startCreateMode} type="button">
          <Plus size={15} />
          新建连接
        </button>

        <div className="sidebar-section-heading">
          <span>连接</span>
          <span>{instances.length}</span>
        </div>
        <label className="search-field">
          <Search size={14} aria-hidden="true" />
          <input
            aria-label="搜索连接"
            onChange={(event) => setInstanceQuery(event.target.value)}
            placeholder="搜索名称、主机或用户"
            value={instanceQuery}
          />
          {instanceQuery ? (
            <button
              aria-label="清除搜索"
              className="search-clear"
              onClick={() => setInstanceQuery("")}
              title="清除搜索"
              type="button"
            >
              <X size={13} />
            </button>
          ) : null}
        </label>

        <div className="instance-list">
          {filteredInstances.map((instance) => (
            <button
              key={instance.instance_id}
              className={
                instance.instance_id === selectedId ? "instance-card active" : "instance-card"
              }
              onClick={() => selectInstance(instance)}
              type="button"
            >
              <span className="instance-icon" aria-hidden="true">
                <Server size={15} />
              </span>
              <div className="instance-title">
                <strong>{instance.name}</strong>
                {instance.has_secret ? <span className="credential-dot" title="凭据已保存" /> : null}
              </div>
              <p>{instance.username}@{instance.host}:{instance.port}</p>
              <small>{instance.instance_id}</small>
            </button>
          ))}

          {instances.length === 0 ? (
            <div className="empty-state">
              <Server size={18} aria-hidden="true" />
              <p>暂无连接</p>
              <span>新建连接后会显示在这里。</span>
            </div>
          ) : filteredInstances.length === 0 ? (
            <div className="empty-state compact">
              <Search size={17} aria-hidden="true" />
              <p>没有匹配结果</p>
            </div>
          ) : null}
        </div>

        <div className="sidebar-bottom">
          <button
            className="sidebar-nav-button"
            onClick={() => setShowConfigDialog(true)}
            type="button"
          >
            <Terminal size={15} />
            <span>MCP 配置</span>
          </button>
          <button
            className={"sidebar-nav-button" + (showSettings ? " active" : "")}
            onClick={showSettings ? closeSettings : openSettings}
            type="button"
          >
            <Settings size={15} />
            <span>设置</span>
          </button>
        </div>
      </aside>

      <main className="content">
        {showSettings ? (
          <SettingsPanel
            appSettings={appSettings}
            loadingWhitelistRules={loadingWhitelistRules}
            whitelistRules={whitelistRules}
            saving={savingSettings}
            restartingMcp={restartingMcp}
            restartResult={restartResult}
            onChangeApprovalLevel={handleChangeApprovalLevel}
            onSaveAutoReviewSettings={handleSaveAutoReviewSettings}
            onRemoveWhitelistRule={handleRemoveWhitelistRule}
            onRestartMcp={handleRestartMcp}
            onSaveWhitelistRule={handleSaveWhitelistRule}
            onToggleWhitelistRule={handleToggleWhitelistRule}
            onClose={closeSettings}
            onDragMouseDown={(event) => void handleDragMouseDown(event)}
          />
        ) : (
          <section className="panel-main">
            <div className="panel-header" onMouseDown={(event) => void handleDragMouseDown(event)}>
              <div className="panel-title-group">
                <span className="panel-eyebrow">{isCreating ? "新建连接" : "SSH 连接"}</span>
                <h2>{isCreating ? "配置远程主机" : draft.name || draft.instance_id}</h2>
                {!isCreating && draft.host ? (
                  <p>{draft.username}@{draft.host}:{draft.port}</p>
                ) : null}
              </div>
              <div className={`status-pill ${statusTone}`} role={statusTone === "danger" ? "alert" : "status"}>
                {statusTone === "success" ? <CheckCircle2 size={14} /> : null}
                {statusTone === "danger" ? <XCircle size={14} /> : null}
                {statusTone === "neutral" ? <Activity size={14} /> : null}
                <span>{status}</span>
              </div>
            </div>

            <div className="tab-bar" role="tablist" aria-label="连接视图">
              <button
                aria-selected={activeTab === "config"}
                className={activeTab === "config" ? "tab active" : "tab"}
                onClick={() => setActiveTab("config")}
                role="tab"
                type="button"
              >
                <SlidersHorizontal size={14} />
                连接配置
              </button>
              <button
                aria-selected={activeTab === "logs"}
                className={activeTab === "logs" ? "tab active" : "tab"}
                onClick={() => setActiveTab("logs")}
                role="tab"
                type="button"
              >
                <ListTree size={14} />
                操作日志
              </button>
            </div>

            {activeTab === "config" ? (
              <form
                className="tab-content connection-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  if (canSubmit) void handleSave();
                }}
              >
                <section className="form-section">
                  <div className="form-section-heading">
                    <span className="section-icon"><Server size={16} /></span>
                    <div>
                      <h3>连接信息</h3>
                      <p>用于定位远程主机并在 MCP 中识别此连接。</p>
                    </div>
                  </div>
                  <div className="form-grid">
                    <label className="field-span-full">
                      <span>SSH 目标</span>
                      <div className="target-row">
                        <div className="input-with-icon">
                          <Terminal size={14} />
                          <input
                            onChange={(event) => setTargetInput(event.target.value)}
                            onKeyDown={(event) => {
                              if (event.key === "Enter") {
                                event.preventDefault();
                                applyTargetInput();
                              }
                            }}
                            placeholder="ssh://root@10.0.0.10:22"
                            value={targetInput}
                          />
                        </div>
                        <button className="secondary-button" onClick={applyTargetInput} type="button">
                          <Zap size={14} />
                          解析
                        </button>
                      </div>
                    </label>
                    <label className="field-span-6">
                      <span>连接 ID</span>
                      <input
                        disabled={!isCreating}
                        onChange={(event) => setDraft({ ...draft, instance_id: event.target.value })}
                        placeholder="prod-server"
                        value={draft.instance_id}
                      />
                    </label>
                    <label className="field-span-6">
                      <span>显示名称</span>
                      <input
                        onChange={(event) => setDraft({ ...draft, name: event.target.value })}
                        placeholder="生产服务器"
                        value={draft.name}
                      />
                    </label>
                    <label className="field-span-6">
                      <span>主机</span>
                      <input
                        onChange={(event) => setDraft({ ...draft, host: event.target.value })}
                        placeholder="10.0.0.10"
                        value={draft.host}
                      />
                    </label>
                    <label className="field-span-2">
                      <span>端口</span>
                      <input
                        min={1}
                        onChange={(event) =>
                          setDraft({
                            ...draft,
                            port: Number.parseInt(event.target.value, 10) || 22,
                          })
                        }
                        type="number"
                        value={draft.port}
                      />
                    </label>
                    <label className="field-span-4">
                      <span>用户名</span>
                      <input
                        onChange={(event) => setDraft({ ...draft, username: event.target.value })}
                        placeholder="root"
                        value={draft.username}
                      />
                    </label>
                  </div>
                </section>

                <section className="form-section">
                  <div className="form-section-heading">
                    <span className="section-icon"><LockKeyhole size={16} /></span>
                    <div>
                      <h3>认证与安全</h3>
                      <p>凭据仅保存在操作系统 Keychain 中。</p>
                    </div>
                  </div>

                  <div className="auth-mode-field">
                    <span>认证方式</span>
                    <div className="segmented-control" role="radiogroup" aria-label="认证方式">
                      <button
                        aria-checked={draft.auth_kind === "password"}
                        className={draft.auth_kind === "password" ? "active" : ""}
                        onClick={() => setDraft({ ...draft, auth_kind: "password" })}
                        role="radio"
                        type="button"
                      >
                        <KeyRound size={14} />
                        密码
                      </button>
                      <button
                        aria-checked={draft.auth_kind === "private_key"}
                        className={draft.auth_kind === "private_key" ? "active" : ""}
                        onClick={() => setDraft({ ...draft, auth_kind: "private_key" })}
                        role="radio"
                        type="button"
                      >
                        <FileKey2 size={14} />
                        私钥
                      </button>
                    </div>
                  </div>

                  {requiresPassword ? (
                    <label className="field-block">
                      <span>SSH 密码</span>
                      <div className="input-with-icon">
                        <KeyRound size={14} />
                        <input
                          autoComplete="new-password"
                          onChange={(event) => setDraft({ ...draft, password: event.target.value })}
                          placeholder={
                            isCreating
                              ? "输入远程账户密码"
                              : draft.has_saved_secret
                                ? "留空则保留已保存的密码"
                                : "输入远程账户密码"
                          }
                          type="password"
                          value={draft.password}
                        />
                      </div>
                    </label>
                  ) : null}

                  {requiresKey ? (
                    <div className="key-fields">
                      <label className="field-block">
                        <span>私钥文件</span>
                        <div className="target-row">
                          <div className="input-with-icon">
                            <FileKey2 size={14} />
                            <input
                              placeholder={isCreating ? "选择本地私钥文件" : "留空则保留已保存的路径"}
                              readOnly
                              value={draft.private_key_path}
                            />
                          </div>
                          <div className="inline-actions">
                            <button
                              className="secondary-button"
                              onClick={() => void handlePickPrivateKeyFile()}
                              type="button"
                            >
                              <FolderOpen size={14} />
                              选择文件
                            </button>
                            {draft.private_key_path ? (
                              <button
                                aria-label="清除私钥文件"
                                className="icon-button ghost-button"
                                onClick={() => setDraft({ ...draft, private_key_path: "" })}
                                title="清除私钥文件"
                                type="button"
                              >
                                <X size={14} />
                              </button>
                            ) : null}
                          </div>
                        </div>
                      </label>
                      <div className="field-divider"><span>或者</span></div>
                      <label className="field-block">
                        <span>直接粘贴私钥内容</span>
                        <textarea
                          onChange={(event) => setDraft({ ...draft, private_key: event.target.value })}
                          placeholder={isCreating ? "粘贴 OpenSSH 私钥内容" : "留空则保留已保存的私钥"}
                          rows={3}
                          value={draft.private_key}
                        />
                      </label>
                      {hasPrivateKeyConflict ? (
                        <div className="inline-error" role="alert">
                          <AlertTriangle size={14} />
                          私钥内容和私钥文件不能同时使用，请保留其中一种。
                        </div>
                      ) : null}
                      <label className="field-block compact-field">
                        <span>私钥口令</span>
                        <input
                          autoComplete="new-password"
                          onChange={(event) => setDraft({ ...draft, passphrase: event.target.value })}
                          placeholder="可选"
                          type="password"
                          value={draft.passphrase}
                        />
                      </label>
                    </div>
                  ) : null}

                  <div className="security-options">
                    <label className="checkbox-row">
                      <input
                        checked={draft.host_key_check}
                        onChange={(event) => setDraft({ ...draft, host_key_check: event.target.checked })}
                        type="checkbox"
                      />
                      <span className="checkbox-indicator"><Check size={12} /></span>
                      <span>
                        <strong>校验主机指纹</strong>
                        <small>要求远程主机存在于 known_hosts。</small>
                      </span>
                    </label>
                    {!isCreating && draft.has_saved_secret ? (
                      <label className="checkbox-row">
                        <input
                          checked={draft.keep_existing_secret}
                          onChange={(event) => setDraft({ ...draft, keep_existing_secret: event.target.checked })}
                          type="checkbox"
                        />
                        <span className="checkbox-indicator"><Check size={12} /></span>
                        <span>
                          <strong>保留已保存凭据</strong>
                          <small>凭据字段留空时继续使用 Keychain 中的值。</small>
                        </span>
                      </label>
                    ) : null}
                  </div>
                </section>

                <section className="form-section notes-section">
                  <label className="field-block">
                    <span>备注</span>
                    <textarea
                      onChange={(event) => setDraft({ ...draft, notes: event.target.value })}
                      placeholder="可选：环境、用途或维护说明"
                      rows={2}
                      value={draft.notes}
                    />
                  </label>
                </section>

                <div className="form-action-bar">
                  <div className="form-action-primary">
                    <button className="primary-button" disabled={saving || !canSubmit} type="submit">
                      {saving ? <LoaderCircle className="spin-icon" size={15} /> : <Save size={15} />}
                      {saving ? "保存中" : "保存连接"}
                    </button>
                    <button
                      className="secondary-button"
                      disabled={testing || !canSubmit}
                      onClick={() => void handleTest()}
                      type="button"
                    >
                      {testing ? <LoaderCircle className="spin-icon" size={15} /> : <Zap size={15} />}
                      {testing ? "测试中" : "测试连接"}
                    </button>
                  </div>
                  {!isCreating ? (
                    <button
                      className="danger-button"
                      onClick={() => setShowDeleteDialog(true)}
                      type="button"
                    >
                      <Trash2 size={14} />
                      删除连接
                    </button>
                  ) : null}
                </div>
              </form>
            ) : (
              <div className="tab-content log-viewer">
                <div className="log-toolbar">
                  <span className="log-summary">
                    {logs.length > 0
                      ? `${logs.length} 条操作记录`
                      : loadingLogs
                        ? "正在加载日志"
                        : "暂无操作记录"}
                  </span>
                  <div className="log-toolbar-actions">
                    <label className="toggle-switch" title={autoRefresh ? "暂停自动刷新" : "恢复自动刷新"}>
                      <input
                        type="checkbox"
                        checked={autoRefresh}
                        onChange={() => setAutoRefresh((value) => !value)}
                      />
                      <span className="toggle-slider" />
                      <span className="toggle-label">自动刷新</span>
                    </label>
                    <button
                      aria-label="刷新日志"
                      className="ghost-button icon-button"
                      disabled={loadingLogs}
                      onClick={() => void loadLogs()}
                      title="刷新日志"
                      type="button"
                    >
                      <RefreshCw className={loadingLogs ? "spin-icon" : ""} size={14} />
                    </button>
                    <div className="stdout-control" aria-label="展开最近 stdout">
                      <ListTree size={13} />
                      <span>输出</span>
                      {[10, 20].map((count) => (
                        <button
                          key={count}
                          className={expandedStdout === count ? "active" : ""}
                          onClick={() => setExpandedStdout((value) => (value === count ? 0 : count as 10 | 20))}
                          title={expandedStdout === count ? "折叠 stdout" : `展开最近 ${count} 条 stdout`}
                          type="button"
                        >
                          {count}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="log-list" ref={logListRef}>
                  {logs.length === 0 && !loadingLogs ? (
                    <div className="log-empty-state">
                      <Activity size={20} />
                      <span>SSH 操作会实时显示在这里</span>
                    </div>
                  ) : null}
                  {logs.map((entry, index) => {
                    const prev = index > 0 ? logs[index - 1] : null;
                    const sessionChange = !prev
                      || prev.client_session_id !== entry.client_session_id
                      || prev.session_id !== entry.session_id;
                    const shouldOpen = expandedStdout > 0
                      && entry.operation === "execute_command"
                      && index >= latestNExecIndex(logs, expandedStdout);

                    return (
                      <div key={entry.id}>
                        {sessionChange ? (
                          <div className="log-separator">
                            <span className="log-separator-label">{formatLogSeparator(entry)}</span>
                          </div>
                        ) : null}
                        <div className="log-entry">
                          <div className="log-entry-meta">
                            <span className="log-time">{formatLogTime(entry.created_at)}</span>
                            <span className="log-client-badge" title={entry.client_session_id || "client session"}>
                              {formatClientLabel(entry)}
                            </span>
                            {entry.session_id ? (
                              <span className="log-session-badge" title={entry.session_id}>
                                ssh:{shortId(entry.session_id)}
                              </span>
                            ) : null}
                            <span className={`log-op-badge log-op-${entry.operation}`}>{entry.operation}</span>
                          </div>
                          <div className="log-entry-body">
                            <LogEntryBody entry={entry} autoOpenStdout={shouldOpen} />
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </section>
        )}
      </main>

      {showConfigDialog ? (
        <div className="dialog-backdrop" onClick={() => setShowConfigDialog(false)} role="presentation">
          <section
            aria-label="MCP 配置"
            className="dialog-shell"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="dialog-header">
              <div className="dialog-title-group">
                <span className="dialog-icon"><Terminal size={17} /></span>
                <div>
                <h2>MCP 配置</h2>
                <p className="dialog-subtitle">
                  {configs ? `命令：${configs.command}` : "正在加载 MCP 配置..."}
                </p>
                </div>
              </div>
              <button
                aria-label="关闭 MCP 配置"
                className="ghost-button icon-button"
                onClick={() => setShowConfigDialog(false)}
                title="关闭"
                type="button"
              >
                <X size={16} />
              </button>
            </div>

            <div className="dialog-grid">
              <article className="config-block">
                <div className="config-block-header">
                  <div>
                    <strong>STDIO</strong>
                    <p>{configs?.command ?? "正在加载..."}</p>
                  </div>
                  <button
                    className="ghost-button"
                    disabled={!configs || !configs.helper_found}
                    onClick={() => configs && configs.helper_found && copyConfig("STDIO", configs.stdio_json)}
                    type="button"
                  >
                    <Clipboard size={14} />
                    复制 JSON
                  </button>
                </div>
                {!configs?.helper_found && configs?.helper_warning ? (
                  <div className="config-warning" role="alert">
                    {configs.helper_warning}
                  </div>
                ) : null}
                <pre>{configs?.stdio_json ?? "正在加载..."}</pre>
              </article>
            </div>
          </section>
        </div>
      ) : null}

      {showDeleteDialog && selectedId ? (
        <div className="dialog-backdrop" onClick={() => setShowDeleteDialog(false)} role="presentation">
          <section
            aria-label="删除连接"
            aria-modal="true"
            className="confirm-dialog"
            onClick={(event) => event.stopPropagation()}
            role="dialog"
          >
            <span className="confirm-icon danger"><Trash2 size={20} /></span>
            <div className="confirm-copy">
              <h2>删除“{draft.name || selectedId}”？</h2>
              <p>连接配置与 Keychain 中的凭据将被移除，正在使用此连接的 SSH 会话也会关闭。</p>
            </div>
            <div className="confirm-actions">
              <button className="secondary-button" onClick={() => setShowDeleteDialog(false)} type="button">
                取消
              </button>
              <button className="danger-button solid" onClick={() => void handleDelete()} type="button">
                <Trash2 size={14} />
                删除连接
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </div>
  );
}

function SettingsPanel({
  appSettings,
  loadingWhitelistRules,
  whitelistRules,
  saving,
  restartingMcp,
  restartResult,
  onChangeApprovalLevel,
  onSaveAutoReviewSettings,
  onRemoveWhitelistRule,
  onRestartMcp,
  onSaveWhitelistRule,
  onToggleWhitelistRule,
  onClose,
  onDragMouseDown,
}: {
  appSettings: AppSettings | null;
  loadingWhitelistRules: boolean;
  whitelistRules: WhitelistRule[];
  saving: boolean;
  restartingMcp: boolean;
  restartResult: { kind: "success" | "error"; message: string } | null;
  onChangeApprovalLevel: (approvalLevel: ApprovalLevel) => void;
  onSaveAutoReviewSettings: (
    autoReview: { base_url: string; model: string },
    apiKey: string,
    clearApiKey: boolean,
  ) => Promise<void>;
  onRemoveWhitelistRule: (id: number) => Promise<void>;
  onRestartMcp: () => Promise<void>;
  onSaveWhitelistRule: (id: number | null, input: WhitelistRuleInput) => Promise<void>;
  onToggleWhitelistRule: (id: number, enabled: boolean) => Promise<void>;
  onClose: () => void;
  onDragMouseDown: (event: React.MouseEvent<HTMLElement>) => void;
}) {
  const [activeSection, setActiveSection] = useState<"security" | "rules" | "mcp">("security");
  const [autoReviewBaseUrl, setAutoReviewBaseUrl] = useState("");
  const [autoReviewModel, setAutoReviewModel] = useState("");
  const [autoReviewApiKey, setAutoReviewApiKey] = useState("");
  const [clearAutoReviewApiKey, setClearAutoReviewApiKey] = useState(false);

  useEffect(() => {
    if (!appSettings) {
      return;
    }
    setAutoReviewBaseUrl(appSettings.auto_review.base_url);
    setAutoReviewModel(appSettings.auto_review.model);
    setAutoReviewApiKey("");
    setClearAutoReviewApiKey(false);
  }, [appSettings]);

  async function saveAutoReviewSettings() {
    try {
      await onSaveAutoReviewSettings(
        {
          base_url: autoReviewBaseUrl,
          model: autoReviewModel,
        },
        autoReviewApiKey,
        clearAutoReviewApiKey,
      );
      setAutoReviewApiKey("");
      setClearAutoReviewApiKey(false);
    } catch {
      // The parent already reports the backend error in the global status bar.
    }
  }

  function restartButtonContent() {
    if (restartingMcp) {
      return (
        <>
          <LoaderCircle className="spin-icon" size={14} />
          重启中
        </>
      );
    }
    if (restartResult) {
      return (
        <>
          {restartResult.kind === "success" ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
          {restartResult.kind === "success" ? "已重启" : "失败"}
        </>
      );
    }
    return (
      <>
        <RotateCcw size={14} />
        重启服务器
      </>
    );
  }

  return (
    <section className="panel-main">
      <div className="panel-header" onMouseDown={onDragMouseDown}>
        <div className="panel-title-group">
          <span className="panel-eyebrow">偏好设置</span>
          <h2>软件设置</h2>
          <p>管理审批体验与本地 MCP 服务。</p>
        </div>
        <button className="secondary-button" onClick={onClose} type="button">
          <ArrowLeft size={14} />
          返回连接
        </button>
      </div>

      <div className="settings-layout">
        <nav className="settings-nav" aria-label="设置分类">
          <button
            aria-current={activeSection === "security" ? "page" : undefined}
            className={activeSection === "security" ? "active" : ""}
            onClick={() => setActiveSection("security")}
            type="button"
          >
            <ShieldCheck size={16} />
            <span>
              <strong>安全</strong>
              <small>审核等级</small>
            </span>
          </button>
          <button
            aria-current={activeSection === "rules" ? "page" : undefined}
            className={activeSection === "rules" ? "active" : ""}
            onClick={() => setActiveSection("rules")}
            type="button"
          >
            <ShieldAlert size={16} />
            <span>
              <strong>全局规则</strong>
              <small>黑白名单</small>
            </span>
          </button>
          <button
            aria-current={activeSection === "mcp" ? "page" : undefined}
            className={activeSection === "mcp" ? "active" : ""}
            onClick={() => setActiveSection("mcp")}
            type="button"
          >
            <Terminal size={16} />
            <span>
              <strong>MCP 服务</strong>
              <small>进程与连接</small>
            </span>
          </button>
        </nav>

        <div className="settings-content">
          {activeSection === "security" ? (
            <section className="settings-section">
              <div className="settings-section-heading">
                <span className="section-icon"><ShieldCheck size={17} /></span>
                <div>
                  <h3>安全</h3>
                  <p>决定未被白名单放行的 SSH 操作如何审核。</p>
                </div>
              </div>
                  <div className="settings-row">
                <div className="settings-item-info">
                  <strong>审核等级</strong>
                  <p>选择系统弹窗、独立 App 弹窗，或跳过审核直接允许访问。</p>
                  <span className="settings-current-value">
                    当前：{approvalLevelLabel(appSettings?.approval_level)}
                  </span>
                </div>
                <div className="settings-choice-list" role="radiogroup" aria-label="审核等级">
                  {approvalLevelOptions.map((option) => {
                    const unavailable =
                      option.value === "auto_agent" && !isAutoReviewConfigured(appSettings);
                    return (
                      <label
                        className={
                          "settings-choice"
                          + (appSettings?.approval_level === option.value ? " active" : "")
                          + (unavailable ? " disabled" : "")
                        }
                        key={option.value}
                        title={unavailable ? "请先配置 Base URL、模型和 API key" : undefined}
                      >
                        <input
                          type="radio"
                          name="approval-level"
                          value={option.value}
                          checked={appSettings?.approval_level === option.value}
                          disabled={saving || !appSettings || unavailable}
                          onChange={() => onChangeApprovalLevel(option.value)}
                        />
                        <span>
                          <strong>{option.label}</strong>
                          <small>{option.description}</small>
                        </span>
                      </label>
                    );
                  })}
                    </div>
                  </div>
                  <div className="settings-row auto-review-settings-row">
                    <div className="settings-item-info">
                      <strong>大模型审核配置</strong>
                      <p>模型会看到 SSH 工具参数、命令、路径和目标主机信息，不会收到 SSH 凭据或命令输出。</p>
                      <span className="settings-current-value">
                        API key：{appSettings?.api_key_configured ? "已配置" : "未配置"}
                      </span>
                    </div>
                    <div className="auto-review-form">
                      <label>
                        <span>Base URL</span>
                        <input
                          autoComplete="url"
                          onChange={(event) => setAutoReviewBaseUrl(event.target.value)}
                          placeholder="https://api.example.com/v1"
                          value={autoReviewBaseUrl}
                        />
                      </label>
                      <label>
                        <span>模型名称</span>
                        <input
                          autoComplete="off"
                          onChange={(event) => setAutoReviewModel(event.target.value)}
                          placeholder="安全审核模型"
                          value={autoReviewModel}
                        />
                      </label>
                      <label>
                        <span>API key</span>
                        <input
                          autoComplete="new-password"
                          onChange={(event) => {
                            setAutoReviewApiKey(event.target.value);
                            setClearAutoReviewApiKey(false);
                          }}
                          placeholder={appSettings?.api_key_configured ? "已保存，留空表示不修改" : "输入 API key"}
                          type="password"
                          value={autoReviewApiKey}
                        />
                      </label>
                      <div className="auto-review-actions">
                        <button
                          className="primary-button"
                          disabled={saving || !appSettings}
                          onClick={() => void saveAutoReviewSettings()}
                          type="button"
                        >
                          <Save size={14} />
                          保存模型配置
                        </button>
                        {appSettings?.api_key_configured ? (
                          <button
                            className={clearAutoReviewApiKey ? "danger-button solid" : "secondary-button"}
                            disabled={saving}
                            onClick={() => setClearAutoReviewApiKey((value) => !value)}
                            type="button"
                          >
                            <Trash2 size={14} />
                            {clearAutoReviewApiKey ? "将清除 API key" : "清除 API key"}
                          </button>
                        ) : null}
                      </div>
                    </div>
                  </div>
                </section>
          ) : activeSection === "rules" ? (
            <WhitelistRulesSection
              loading={loadingWhitelistRules}
              rules={whitelistRules}
              saving={saving}
              onRemove={onRemoveWhitelistRule}
              onSave={onSaveWhitelistRule}
              onToggle={onToggleWhitelistRule}
            />
          ) : (
            <section className="settings-section">
              <div className="settings-section-heading">
                <span className="section-icon"><Terminal size={17} /></span>
                <div>
                  <h3>MCP 服务</h3>
                  <p>处理后台进程异常或客户端无法重连的情况。</p>
                </div>
              </div>
              <div className="settings-row danger-zone">
                <div className="settings-item-info">
                  <strong>重启 MCP 服务器</strong>
                  <p>结束当前进程并清理残留文件。IDE 通常会在数秒后自动重连，正在执行的操作会中断。</p>
                </div>
                <button
                  className={"danger-button" + (restartResult?.kind === "success" ? " feedback-success" : "") + (restartResult?.kind === "error" ? " feedback-error" : "")}
                  disabled={restartingMcp}
                  onClick={() => void onRestartMcp()}
                  type="button"
                >
                  {restartButtonContent()}
                </button>
              </div>

              {restartResult ? (
                <div className={"settings-feedback " + restartResult.kind} role="status">
                  {restartResult.kind === "success" ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
                  {restartResult.message}
                </div>
              ) : null}
            </section>
          )}
        </div>
      </div>
    </section>
  );
}

function WhitelistRulesSection({
  loading,
  rules,
  saving,
  onRemove,
  onSave,
  onToggle,
}: {
  loading: boolean;
  rules: WhitelistRule[];
  saving: boolean;
  onRemove: (id: number) => Promise<void>;
  onSave: (id: number | null, input: WhitelistRuleInput) => Promise<void>;
  onToggle: (id: number, enabled: boolean) => Promise<void>;
}) {
  const [actionFilter, setActionFilter] = useState<"all" | RuleAction>("all");
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editorError, setEditorError] = useState<string | null>(null);
  const [draft, setDraft] = useState<WhitelistRuleInput>(emptyWhitelistRuleInput());

  const filteredRules = actionFilter === "all"
    ? rules
    : rules.filter((rule) => rule.action === actionFilter);

  function openNewRule() {
    setEditingId(null);
    setDraft(emptyWhitelistRuleInput());
    setEditorError(null);
    setEditorOpen(true);
  }

  function openEditRule(rule: WhitelistRule) {
    setEditingId(rule.id);
    setDraft({
      rule_type: rule.rule_type,
      pattern: rule.pattern,
      action: rule.action,
    });
    setEditorError(null);
    setEditorOpen(true);
  }

  function closeEditor() {
    setEditorOpen(false);
    setEditorError(null);
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const pattern = draft.pattern.trim();
    if (!pattern) {
      setEditorError("请输入匹配规则。");
      return;
    }

    try {
      await onSave(editingId, { ...draft, pattern });
      closeEditor();
    } catch {
      // The parent already reports the backend error in the global status bar.
    }
  }

  async function handleRemove(rule: WhitelistRule) {
    if (!window.confirm(`确定删除规则“${rule.pattern}”吗？`)) {
      return;
    }
    await onRemove(rule.id);
    if (editingId === rule.id) {
      closeEditor();
    }
  }

  return (
    <section className="settings-section rules-section">
      <div className="settings-section-heading">
        <span className="section-icon"><ShieldAlert size={17} /></span>
        <div>
          <h3>全局访问规则</h3>
          <p>对所有 SSH 连接生效，规则修改后立即应用。</p>
        </div>
      </div>

      <div className="rules-toolbar">
        <label className="rule-filter-label">
          <span>显示</span>
          <select
            aria-label="筛选规则动作"
            className="rule-filter"
            value={actionFilter}
            onChange={(event) => setActionFilter(event.target.value as "all" | RuleAction)}
          >
            <option value="all">全部规则</option>
            <option value="allow">允许访问</option>
            <option value="require_approval">要求审核</option>
            <option value="deny">禁止访问</option>
          </select>
        </label>
        <button className="primary-button" onClick={openNewRule} type="button">
          <Plus size={14} />
          添加规则
        </button>
      </div>

      {editorOpen ? (
        <form className="rule-editor" onSubmit={(event) => void handleSubmit(event)}>
          <div className="rule-editor-heading">
            <div>
              <strong>{editingId === null ? "添加全局规则" : "编辑全局规则"}</strong>
              <span>规则按完整字符串匹配；命令支持 `*` 和 `?` 通配符。</span>
            </div>
            <button
              aria-label="关闭规则编辑器"
              className="secondary-button icon-button"
              onClick={closeEditor}
              title="关闭"
              type="button"
            >
              <X size={14} />
            </button>
          </div>
          <div className="rule-form-grid">
            <label>
              <span>处理方式</span>
              <select
                value={draft.action}
                onChange={(event) => setDraft({ ...draft, action: event.target.value as RuleAction })}
              >
                <option value="allow">允许访问（白名单）</option>
                <option value="require_approval">要求审核</option>
                <option value="deny">禁止访问（黑名单）</option>
              </select>
            </label>
            <label>
              <span>匹配维度</span>
              <select
                value={draft.rule_type}
                onChange={(event) => setDraft({ ...draft, rule_type: event.target.value as RuleType })}
              >
                <option value="tool">工具名</option>
                <option value="command">命令</option>
                <option value="path">路径</option>
                <option value="instance">实例 ID</option>
              </select>
            </label>
            <label className="rule-pattern-field">
              <span>匹配规则</span>
              <input
                autoComplete="off"
                autoFocus
                className="mono-input"
                placeholder={rulePatternPlaceholder(draft.rule_type)}
                spellCheck={false}
                value={draft.pattern}
                onChange={(event) => setDraft({ ...draft, pattern: event.target.value })}
              />
            </label>
          </div>
          {editorError ? <p className="rule-editor-error" role="alert">{editorError}</p> : null}
          <div className="rule-editor-actions">
            <button className="secondary-button" onClick={closeEditor} type="button">
              取消
            </button>
            <button className="primary-button" disabled={saving} type="submit">
              <Save size={14} />
              {editingId === null ? "添加规则" : "保存修改"}
            </button>
          </div>
        </form>
      ) : null}

      <div className="rules-summary" aria-live="polite">
        <span>共 {rules.length} 条规则</span>
        <span>启用 {rules.filter((rule) => rule.enabled).length} 条</span>
      </div>

      {loading ? (
        <div className="rules-empty-state">正在加载规则...</div>
      ) : filteredRules.length === 0 ? (
        <div className="rules-empty-state">
          <ShieldAlert size={18} />
          <span>{rules.length === 0 ? "暂无全局规则" : "没有符合筛选条件的规则"}</span>
        </div>
      ) : (
        <div className="rules-list" role="list">
          {filteredRules.map((rule) => (
            <article className={"rule-row" + (rule.enabled ? "" : " disabled")} key={rule.id}>
              <label className="rule-enabled-control">
                <input
                  aria-label={`${rule.pattern}规则`}
                  checked={rule.enabled}
                  disabled={saving}
                  type="checkbox"
                  onChange={(event) => void onToggle(rule.id, event.target.checked)}
                />
              </label>
              <div className="rule-row-main">
                <div className="rule-row-heading">
                  <span className={`rule-action-badge ${rule.action}`}>
                    {ruleActionLabel(rule.action)}
                  </span>
                  <span className="rule-type-label">{ruleTypeLabel(rule.rule_type)}</span>
                  {rule.is_builtin ? <span className="rule-builtin-label">默认</span> : null}
                </div>
                <code className="rule-pattern">{rule.pattern}</code>
              </div>
              <div className="rule-row-actions">
                <button
                  aria-label={`编辑规则 ${rule.pattern}`}
                  className="secondary-button icon-button"
                  disabled={saving}
                  onClick={() => openEditRule(rule)}
                  title="编辑规则"
                  type="button"
                >
                  <Pencil size={14} />
                </button>
                <button
                  aria-label={`删除规则 ${rule.pattern}`}
                  className="danger-button icon-button"
                  disabled={saving}
                  onClick={() => void handleRemove(rule)}
                  title="删除规则"
                  type="button"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function emptyWhitelistRuleInput(): WhitelistRuleInput {
  return {
    rule_type: "tool",
    pattern: "",
    action: "allow",
  };
}

function ruleActionLabel(action: RuleAction): string {
  switch (action) {
    case "allow":
      return "允许访问";
    case "require_approval":
      return "要求审核";
    case "deny":
      return "禁止访问";
  }
}

function ruleTypeLabel(ruleType: RuleType): string {
  switch (ruleType) {
    case "tool":
      return "工具";
    case "command":
      return "命令";
    case "path":
      return "路径";
    case "instance":
      return "实例";
  }
}

function rulePatternPlaceholder(ruleType: RuleType): string {
  switch (ruleType) {
    case "tool":
      return "execute_command 或 *";
    case "command":
      return "ls * 或 rm -rf *";
    case "path":
      return "/srv/reports/*";
    case "instance":
      return "production 或 prod-*";
  }
}

const approvalLevelOptions: Array<{
  value: ApprovalLevel;
  label: string;
  description: string;
}> = [
  {
    value: "system_dialog",
    label: "系统弹窗审核",
    description: "使用操作系统原生对话框确认操作。",
  },
  {
    value: "app_dialog",
    label: "App 弹窗审核",
    description: "使用 Xiic 独立审批窗口确认操作。",
  },
  {
    value: "allow_all",
    label: "完全允许访问",
    description: "未被拒绝规则拦截的操作会直接执行。",
  },
  {
    value: "auto_agent",
    label: "大模型自动审核",
    description: "将未被白名单放行的操作交给配置的模型判断。",
  },
];

function approvalLevelLabel(level: ApprovalLevel | undefined): string {
  return approvalLevelOptions.find((option) => option.value === level)?.label ?? "加载中";
}

function isAutoReviewConfigured(settings: AppSettings | null): boolean {
  return Boolean(
    settings
      && settings.api_key_configured
      && settings.auto_review.base_url.trim()
      && settings.auto_review.model.trim(),
  );
}

function formatLogTime(iso: string): string {
  try {
    const date = new Date(iso);
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
  } catch {
    return iso;
  }
}

function parseLogInstanceName(entry: OperationLogEntry): string {
  try {
    const d = JSON.parse(entry.details);
    return (d.instance_name as string) || entry.instance_id;
  } catch {
    return entry.instance_id;
  }
}

function shortId(value: string): string {
  return value ? value.slice(0, 8) : "-";
}

function formatClientLabel(entry: OperationLogEntry): string {
  const client = entry.client_id || "legacy";
  const session = entry.client_session_id ? `:${shortId(entry.client_session_id)}` : "";
  return `${client}${session}`;
}

function formatLogSeparator(entry: OperationLogEntry): string {
  const client = formatClientLabel(entry);
  const ssh = entry.session_id ? `ssh ${shortId(entry.session_id)}` : "no ssh session";
  const target = parseLogInstanceName(entry);
  return `${client} · ${ssh} · ${target}`;
}

function latestNExecIndex(logs: OperationLogEntry[], n: number): number {
  if (n === 0) return logs.length;
  let count = 0;
  for (let i = logs.length - 1; i >= 0; i--) {
    if (logs[i].operation === "execute_command") {
      count++;
      if (count === n) return i;
    }
  }
  return 0;
}

function LogEntryBody({ entry, autoOpenStdout }: { entry: OperationLogEntry; autoOpenStdout: boolean }) {
  let parsed: Record<string, unknown> = {};
  try {
    parsed = JSON.parse(entry.details);
  } catch {
    return <pre className="log-body">{entry.details}</pre>;
  }

  if (entry.operation === "execute_command") {
    return (
      <div className="log-body">
        <span className="log-cmd">
          <span className="log-cmd-prefix">$</span> {String(parsed.command ?? "")}
        </span>
        <span className="log-exit">
          exit:{String(parsed.exit_code ?? "?")}
        </span>
        {parsed.stdout ? (
          <details className="log-output-block" open={autoOpenStdout}>
            <summary className="log-output-summary">stdout</summary>
            <pre className="log-output">{String(parsed.stdout)}</pre>
          </details>
        ) : null}
        {parsed.stderr ? (
          <details className="log-output-block" open={autoOpenStdout}>
            <summary className="log-output-summary">stderr</summary>
            <pre className="log-output log-output-stderr">{String(parsed.stderr)}</pre>
          </details>
        ) : null}
      </div>
    );
  }

  if (entry.operation === "create_session") {
    const hostInfo = parsed.host
      ? ` (${String(parsed.name ?? parsed.instance_id)} @ ${String(parsed.host)}:${String(parsed.port)})`
      : "";
    return (
      <div className="log-body">
        <span>session: {entry.session_id.slice(0, 8)}...{hostInfo}</span>
      </div>
    );
  }

  if (entry.operation === "client_connected" || entry.operation === "client_disconnected") {
    return (
      <div className="log-body">
        <span>{formatClientLabel(entry)}</span>
      </div>
    );
  }

  if (entry.operation === "upload_file") {
    return (
      <div className="log-body">
        <span className="log-path">{String(parsed.local_path ?? "")}</span>
        <span>→</span>
        <span className="log-path">{String(parsed.remote_path ?? "")}</span>
        <span className="log-meta">{Number(parsed.bytes_written ?? 0)} bytes</span>
      </div>
    );
  }

  if (entry.operation === "download_file") {
    return (
      <div className="log-body">
        <span className="log-path">{String(parsed.remote_path ?? "")}</span>
        <span>→</span>
        <span className="log-path">{String(parsed.local_path ?? "")}</span>
        <span className="log-meta">{Number(parsed.size ?? 0)} bytes</span>
      </div>
    );
  }

  return <pre className="log-body">{entry.details}</pre>;
}

function asMessage(error: unknown): string {
  if (typeof error === "string") {
    return error;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "发生了未知错误。";
}

function parseSshTarget(input: string): ParsedTarget | null {
  const raw = input.trim();
  if (!raw) {
    return null;
  }

  if (raw.startsWith("ssh://")) {
    try {
      const url = new URL(raw);
      if (!url.hostname) {
        return null;
      }

      return {
        host: url.hostname,
        port: url.port ? Number.parseInt(url.port, 10) || 22 : 22,
        username: decodeURIComponent(url.username || ""),
      };
    } catch {
      return null;
    }
  }

  const atIndex = raw.lastIndexOf("@");
  const username = atIndex >= 0 ? raw.slice(0, atIndex) : "";
  const hostPart = atIndex >= 0 ? raw.slice(atIndex + 1) : raw;

  if (!hostPart) {
    return null;
  }

  const colonIndex = hostPart.lastIndexOf(":");
  if (colonIndex > -1 && hostPart.indexOf("]") === -1) {
    const host = hostPart.slice(0, colonIndex);
    const portText = hostPart.slice(colonIndex + 1);
    if (!host) {
      return null;
    }
    return {
      host,
      port: Number.parseInt(portText, 10) || 22,
      username,
    };
  }

  return {
    host: hostPart,
    port: 22,
    username,
  };
}

function formatTarget(username: string, host: string, port: number): string {
  const prefix = username ? `${username}@` : "";
  return `${prefix}${host}:${port}`;
}
