import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { listen } from "@tauri-apps/api/event";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";

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
  passphrase: string;
  keep_existing_secret: boolean;
};

type TestConnectionResult = {
  success: boolean;
  message: string;
};

type McpConfigBundle = {
  command: string;
  args: string[];
  stdio_json: string;
};

type OperationLogEntry = {
  id: number;
  session_id: string;
  instance_id: string;
  operation: string;
  details: string;
  created_at: string;
};

type AppSettings = {
  use_system_approval: boolean;
};

type ParsedTarget = {
  host: string;
  port: number;
  username: string;
};

const appWindow = getCurrentWindow();

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
  passphrase: "",
  keep_existing_secret: false,
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
    passphrase: "",
    keep_existing_secret: instance.has_secret,
  };
}

export default function App() {
  const [instances, setInstances] = useState<InstanceSummary[]>([]);
  const [draft, setDraft] = useState<InstanceDraft>(emptyDraft());
  const [targetInput, setTargetInput] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isCreating, setIsCreating] = useState(true);
  const [configs, setConfigs] = useState<McpConfigBundle | null>(null);
  const [showConfigDialog, setShowConfigDialog] = useState(false);
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
  const [savingSettings, setSavingSettings] = useState(false);
  const [restartingMcp, setRestartingMcp] = useState(false);
  const [restartResult, setRestartResult] = useState<{ kind: "success" | "error"; message: string } | null>(null);
  const logListRef = useRef<HTMLDivElement>(null);
  const activeTabRef = useRef(activeTab);
  const autoRefreshRef = useRef(autoRefresh);

  useEffect(() => {
    void loadData();
  }, []);

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
          setDraft(fromSummary(selected));
          setIsCreating(false);
          return;
        }
      }

      if (loadedInstances.length > 0) {
        setSelectedId(loadedInstances[0].instance_id);
        setDraft(fromSummary(loadedInstances[0]));
        setTargetInput(formatTarget(
          loadedInstances[0].username,
          loadedInstances[0].host,
          loadedInstances[0].port,
        ));
        setIsCreating(false);
      } else {
        startCreateMode();
      }
      setStatus("已就绪。");
      setStatusTone("neutral");
    } catch (error) {
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
      setLastLogId(sorted.length > 0 ? sorted[sorted.length - 1].id : 0);
    } catch (error) {
      setStatus(asMessage(error));
      setStatusTone("danger");
    } finally {
      setLoadingLogs(false);
    }
  }

  async function loadNewLogs() {
    if (lastLogId === 0) {
      void loadLogs();
      return;
    }
    try {
      const entries = await invoke<OperationLogEntry[]>("get_operation_logs_since", {
        sinceId: lastLogId,
        limit: 200,
      });
      if (entries.length === 0) return;
      setLogs((prev) => {
        const existingIds = new Set(prev.map((e) => e.id));
        const newEntries = entries.filter((e) => !existingIds.has(e.id));
        return [...prev, ...newEntries];
      });
      const maxId = entries.reduce((max, e) => Math.max(max, e.id), lastLogId);
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
  }

  function selectInstance(instance: InstanceSummary) {
    setSelectedId(instance.instance_id);
    setDraft(fromSummary(instance));
    setTargetInput(formatTarget(instance.username, instance.host, instance.port));
    setIsCreating(false);
    setStatus(`正在编辑 ${instance.name}。`);
    setStatusTone("neutral");
  }

  async function handleSave() {
    setSaving(true);
    try {
      const saved = await invoke<InstanceSummary>("save_instance", { draft });
      await loadData();
      setSelectedId(saved.instance_id);
      setDraft(fromSummary(saved));
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
    const confirmed = window.confirm(`确定删除连接“${selectedId}”吗？`);
    if (!confirmed) {
      return;
    }

    try {
      await invoke("delete_instance", { instanceId: selectedId });
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
    try {
      const settings = await invoke<AppSettings>("get_settings");
      setAppSettings(settings);
    } catch {
      // ignore loading failure
    }
  }

  async function handleToggleSystemApproval(useSystem: boolean) {
    setSavingSettings(true);
    const newSettings: AppSettings = { use_system_approval: useSystem };
    try {
      await invoke("save_settings", { settings: newSettings });
      setAppSettings(newSettings);
      setStatus(useSystem ? "已启用系统弹窗审批。" : "已禁用系统弹窗审批。");
      setStatusTone("success");
    } catch (error) {
      setStatus(asMessage(error));
      setStatusTone("danger");
    } finally {
      setSavingSettings(false);
    }
  }

  async function handleRestartMcp() {
    const confirmed = window.confirm(
      "确定要重启 MCP 服务器吗？\n\n任何正在进行的 SSH 操作将被中断，IDE 将在几秒后自动重新连接。"
    );
    if (!confirmed) return;

    setRestartingMcp(true);
    setRestartResult(null);
    try {
      const msg = await invoke<string>("restart_mcp");
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

  async function handleDragMouseDown(event: React.MouseEvent<HTMLDivElement>) {
    if (event.button !== 0) {
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
      <div
        aria-hidden="true"
        className="drag-strip"
        onMouseDown={(event) => void handleDragMouseDown(event)}
      />

      <aside className="sidebar">
        <div className="sidebar-top">
          <div className="brand">
            <div className="brand-mark" aria-hidden="true">
              <svg viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg">
                <rect x="4" y="4" width="40" height="40" rx="9" fill="#ffffff" stroke="#d7dee9" />
                <path d="M16 18L22 24L16 30" stroke="#203044" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round" />
                <path d="M27 30H33" stroke="#d49139" strokeWidth="3.2" strokeLinecap="round" />
                <circle cx="31" cy="17" r="2.5" fill="#d49139" />
              </svg>
            </div>
            <div className="brand-copy">
              <h1>Xiic SSH 管理器</h1>
              <p>本地连接与 MCP 接入</p>
            </div>
          </div>
        </div>

        <button className="ghost-button" onClick={startCreateMode} type="button">
          + 新建连接
        </button>

        <div className="instance-list">
          {instances.map((instance) => (
            <button
              key={instance.instance_id}
              className={
                instance.instance_id === selectedId ? "instance-card active" : "instance-card"
              }
              onClick={() => selectInstance(instance)}
              type="button"
            >
              <div className="instance-title">
                <strong>{instance.name}</strong>
                <span>{instance.auth_kind === "password" ? "密码" : "私钥"}</span>
              </div>
              <p>{instance.host}:{instance.port}</p>
              <small>{instance.username}@{instance.instance_id}</small>
            </button>
          ))}

          {instances.length === 0 ? (
            <div className="empty-state">
              <p>还没有已保存的连接。</p>
              <span>请先在右侧创建连接，并在保存前测试是否可用。</span>
            </div>
          ) : null}
        </div>

        <div className="sidebar-bottom">
          <button
            className={"sidebar-settings-btn" + (showSettings ? " active" : "")}
            onClick={showSettings ? closeSettings : openSettings}
            type="button"
          >
            <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="8" cy="8" r="2.5" />
              <path d="M8 1v2M8 13v2M1 8h2M13 8h2M2.5 2.5l1.5 1.5M12 12l1.5 1.5M2.5 13.5l1.5-1.5M12 4l1.5-1.5" />
            </svg>
            <span>设置</span>
          </button>
        </div>
      </aside>

      <main className="content">
        {showSettings ? (
          <SettingsPanel
            appSettings={appSettings}
            saving={savingSettings}
            restartingMcp={restartingMcp}
            restartResult={restartResult}
            onToggleSystemApproval={handleToggleSystemApproval}
            onRestartMcp={handleRestartMcp}
            onClose={closeSettings}
          />
        ) : (
        <section className="panel-main">
          <div className="panel-header">
            <div>
              <h2>{isCreating ? "新的 SSH 配置" : draft.name || draft.instance_id}</h2>
            </div>
            <div className="header-actions">
              <button
                className="ghost-button utility-button"
                disabled={!configs}
                onClick={() => setShowConfigDialog(true)}
                type="button"
              >
                MCP 配置
              </button>
              <div className={`status-pill ${statusTone}`}>{status}</div>
            </div>
          </div>

          <div className="tab-bar">
            <button
              className={activeTab === "config" ? "tab active" : "tab"}
              onClick={() => setActiveTab("config")}
              type="button"
            >
              配置
            </button>
            <button
              className={activeTab === "logs" ? "tab active" : "tab"}
              onClick={() => setActiveTab("logs")}
              type="button"
            >
              操作日志
            </button>
          </div>

          {activeTab === "config" ? (
            <div className="tab-content">
              <div className="form-grid">
                <label className="field-span-2">
                  <span>SSH 目标</span>
                  <div className="target-row">
                    <input
                      onChange={(event) => setTargetInput(event.target.value)}
                      placeholder="例如：ssh://root@10.0.0.10:22 或 root@10.0.0.10"
                      value={targetInput}
                    />
                    <button className="ghost-button" onClick={applyTargetInput} type="button">
                      解析
                    </button>
                  </div>
                </label>
                <label>
                  <span>连接 ID</span>
                  <input
                    disabled={!isCreating}
                    onChange={(event) => setDraft({ ...draft, instance_id: event.target.value })}
                    placeholder="例如：prod-server"
                    value={draft.instance_id}
                  />
                </label>
                <label>
                  <span>显示名称</span>
                  <input
                    onChange={(event) => setDraft({ ...draft, name: event.target.value })}
                    placeholder="例如：生产服务器"
                    value={draft.name}
                  />
                </label>
                <label>
                  <span>主机</span>
                  <input
                    onChange={(event) => setDraft({ ...draft, host: event.target.value })}
                    placeholder="10.0.0.10"
                    value={draft.host}
                  />
                </label>
                <label>
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
                <label>
                  <span>用户名</span>
                  <input
                    onChange={(event) => setDraft({ ...draft, username: event.target.value })}
                    placeholder="root"
                    value={draft.username}
                  />
                </label>
                <label>
                  <span>认证方式</span>
                  <select
                    onChange={(event) =>
                      setDraft({
                        ...draft,
                        auth_kind: event.target.value as AuthKind,
                      })
                    }
                    value={draft.auth_kind}
                  >
                    <option value="password">密码</option>
                    <option value="private_key">私钥</option>
                  </select>
                </label>
              </div>

              <div className="toggle-row">
                <label className="checkbox">
                  <input
                    checked={draft.host_key_check}
                    onChange={(event) =>
                      setDraft({ ...draft, host_key_check: event.target.checked })
                    }
                    type="checkbox"
                  />
                  <span>按 known_hosts 校验主机指纹</span>
                </label>

                {!isCreating ? (
                  <label className="checkbox">
                    <input
                      checked={draft.keep_existing_secret}
                      onChange={(event) =>
                        setDraft({ ...draft, keep_existing_secret: event.target.checked })
                      }
                      type="checkbox"
                    />
                    <span>如果密钥字段为空，则保留已存凭据</span>
                  </label>
                ) : null}
              </div>

              {requiresPassword ? (
                <label className="field-block">
                  <span>SSH 密码</span>
                  <input
                    onChange={(event) => setDraft({ ...draft, password: event.target.value })}
                    placeholder={
                      isCreating
                        ? "远程账户密码"
                        : "留空则保留已保存的 SSH 密码"
                    }
                    type="password"
                    value={draft.password}
                  />
                </label>
              ) : null}

              {requiresKey ? (
                <>
                  <label className="field-block">
                    <span>SSH 私钥</span>
                    <textarea
                      onChange={(event) => setDraft({ ...draft, private_key: event.target.value })}
                      placeholder={
                        isCreating
                          ? "粘贴 OpenSSH 私钥内容"
                          : "留空则保留已保存的私钥"
                      }
                      rows={4}
                      value={draft.private_key}
                    />
                  </label>
                  <label className="field-block">
                    <span>私钥口令</span>
                    <input
                      onChange={(event) => setDraft({ ...draft, passphrase: event.target.value })}
                      placeholder="可选口令"
                      type="password"
                      value={draft.passphrase}
                    />
                  </label>
                </>
              ) : null}

              <label className="field-block">
                <span>备注</span>
                <textarea
                  onChange={(event) => setDraft({ ...draft, notes: event.target.value })}
                  placeholder="可选备注、标签或使用说明"
                  rows={2}
                  value={draft.notes}
                />
              </label>

              <div className="action-row">
                <button className="primary-button" disabled={saving} onClick={handleSave} type="button">
                  {saving ? "保存中..." : "保存连接"}
                </button>
                <button className="secondary-button" disabled={testing} onClick={handleTest} type="button">
                  {testing ? "测试中..." : "测试连接"}
                </button>
                {!isCreating ? (
                  <button className="danger-button" onClick={handleDelete} type="button">
                    删除
                  </button>
                ) : null}
              </div>
            </div>
          ) : (
            <div className="tab-content log-viewer">
              <div className="log-toolbar">
                <span className="log-summary">
                  {logs.length > 0
                    ? `共 ${logs.length} 条操作记录`
                    : loadingLogs
                      ? "加载中..."
                      : "暂无操作记录"}
                </span>
                <div className="log-toolbar-actions">
                  <label className="toggle-switch" title={autoRefresh ? "暂停自动刷新" : "恢复自动刷新"}>
                    <input
                      type="checkbox"
                      checked={autoRefresh}
                      onChange={() => setAutoRefresh((v) => !v)}
                    />
                    <span className="toggle-slider" />
                    <span className="toggle-label">自动</span>
                  </label>
                  <button
                    className="ghost-button icon-button"
                    disabled={loadingLogs}
                    onClick={() => void loadLogs()}
                    title="手动刷新"
                    type="button"
                  >
                    <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M1 8a7 7 0 0 1 13.2-3.2M15 8a7 7 0 0 1-13.2 3.2" />
                      <path d="M14 2v4h-4M2 14v-4h4" />
                    </svg>
                  </button>
                  <button
                    className={`ghost-button icon-button${expandedStdout === 10 ? " active" : ""}`}
                    onClick={() => setExpandedStdout((v) => (v === 10 ? 0 : 10))}
                    title={expandedStdout === 10 ? "折叠 stdout" : "展开最近 10 条 stdout"}
                    type="button"
                  >
                    <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M4 6h8M8 2v8" />
                    </svg>
                    <span className="icon-badge">10</span>
                  </button>
                  <button
                    className={`ghost-button icon-button${expandedStdout === 20 ? " active" : ""}`}
                    onClick={() => setExpandedStdout((v) => (v === 20 ? 0 : 20))}
                    title={expandedStdout === 20 ? "折叠 stdout" : "展开最近 20 条 stdout"}
                    type="button"
                  >
                    <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M4 6h8M8 2v8" />
                    </svg>
                    <span className="icon-badge">20</span>
                  </button>
                </div>
              </div>

              <div className="log-list" ref={logListRef}>
                {logs.map((entry, index) => {
                  const prev = index > 0 ? logs[index - 1] : null;
                  const sessionChange = !prev || prev.session_id !== entry.session_id;
                  const shouldOpen = expandedStdout > 0
                    && entry.operation === "execute_command"
                    && index >= latestNExecIndex(logs, expandedStdout)
                    && entry.operation === "execute_command";

                  return (
                    <div key={entry.id}>
                      {sessionChange ? (
                        <div className="log-separator">
                          <span className="log-separator-label">
                            {parseLogInstanceName(entry)}
                          </span>
                        </div>
                      ) : null}
                      <div className="log-entry">
                        <div className="log-entry-meta">
                          <span className="log-time">{formatLogTime(entry.created_at)}</span>
                          <span className={`log-op-badge log-op-${entry.operation}`}>
                            {entry.operation}
                          </span>
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
              <div>
                <h2>MCP 配置</h2>
                <p className="dialog-subtitle">
                  {configs ? `命令：${configs.command}` : "正在加载 MCP 配置..."}
                </p>
              </div>
              <button
                className="ghost-button utility-button"
                onClick={() => setShowConfigDialog(false)}
                type="button"
              >
                关闭
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
                    className="ghost-button utility-button"
                    disabled={!configs}
                    onClick={() => configs && copyConfig("STDIO", configs.stdio_json)}
                    type="button"
                  >
                    复制 JSON
                  </button>
                </div>
                <pre>{configs?.stdio_json ?? "正在加载..."}</pre>
              </article>
            </div>
          </section>
        </div>
      ) : null}
    </div>
  );
}

function SettingsPanel({
  appSettings,
  saving,
  restartingMcp,
  onToggleSystemApproval,
  onRestartMcp,
  onClose,
}: {
  appSettings: AppSettings | null;
  saving: boolean;
  restartingMcp: boolean;
  onToggleSystemApproval: (useSystem: boolean) => void;
  onRestartMcp: () => Promise<void>;
  onClose: () => void;
}) {
  return (
    <section className="panel-main">
      <div className="panel-header">
        <div>
          <h2>软件设置</h2>
        </div>
        <div className="header-actions">
          <button className="ghost-button utility-button" onClick={onClose} type="button">
            返回
          </button>
        </div>
      </div>

      <div className="settings-shell">
        <div className="settings-section">
          <h3 className="settings-section-title">审批</h3>
          <p className="settings-section-desc">配置 SSH 操作执行时的审批行为。</p>

          <div className="settings-item">
            <div className="settings-item-info">
              <strong>启用系统弹窗进行审核</strong>
              <p>开启后，所有需审批的 SSH 操作将直接使用系统原生对话框，不再弹出独立的审批窗口。</p>
            </div>
            <label className="toggle-switch settings-toggle">
              <input
                type="checkbox"
                checked={appSettings?.use_system_approval ?? false}
                disabled={saving}
                onChange={(e) => onToggleSystemApproval(e.target.checked)}
              />
              <span className="toggle-slider" />
              <span className="toggle-label">{appSettings?.use_system_approval ? "开启" : "关闭"}</span>
            </label>
          </div>
        </div>

        <div className="settings-section">
          <h3 className="settings-section-title">MCP 服务器</h3>
          <p className="settings-section-desc">管理 MCP 后台进程。如果服务器意外退出导致工具调用超时，可尝试重启。</p>

          <div className="settings-item">
            <div className="settings-item-info">
              <strong>重启 MCP 服务器</strong>
              <p>结束当前 MCP 进程并清理残留文件，IDE 将在几秒后自动重连。正在进行的操作将被中断。</p>
            </div>
            <button
              className="danger-button"
              disabled={restartingMcp}
              onClick={onRestartMcp}
              style={{ flexShrink: 0 }}
              type="button"
            >
              {restartingMcp ? "重启中..." : "重启服务器"}
            </button>
          </div>
        </div>
      </div>
    </section>
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

  if (entry.operation === "upload_file") {
    return (
      <div className="log-body">
        <span className="log-path">{String(parsed.remote_path ?? "")}</span>
        <span className="log-meta">{Number(parsed.bytes_written ?? 0)} bytes</span>
      </div>
    );
  }

  if (entry.operation === "download_file") {
    return (
      <div className="log-body">
        <span className="log-path">{String(parsed.remote_path ?? "")}</span>
        <span className="log-meta">{Number(parsed.size ?? 0)} bytes · {String(parsed.encoding ?? "")}</span>
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
