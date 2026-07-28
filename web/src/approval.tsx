import { useEffect, useState, type ReactNode } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  Check,
  CheckCheck,
  Clock3,
  Copy,
  FileText,
  Server,
  ShieldAlert,
  Terminal,
  X,
} from "lucide-react";

type ApprovalOperationMetadata = {
  tool_name: string;
  command: string | null;
  remote_path: string | null;
  local_path: string | null;
  instance_id: string | null;
  overwrite: boolean | null;
};

type ApprovalRequest = {
  kind: string;
  request_id: string;
  message: string;
  approval_kind?: "normal" | "high_risk";
  metadata: ApprovalOperationMetadata;
};

type ApprovalRequestedEvent = {
  request: ApprovalRequest;
  pending_count: number;
};

type ApprovalResolvedEvent = {
  request_id: string;
  accepted: boolean;
  pending_count: number;
};

const approvalWindow = isTauri() ? getCurrentWindow() : null;

export default function ApprovalApp() {
  const [activeApproval, setActiveApproval] = useState<ApprovalRequest | null>(null);
  const [pendingApprovalCount, setPendingApprovalCount] = useState(0);
  const [resolvingApproval, setResolvingApproval] = useState(false);
  const [copiedCommand, setCopiedCommand] = useState(false);
  const [status, setStatus] = useState("等待审批请求…");

  useEffect(() => {
    if (!approvalWindow) {
      return;
    }
    void approvalWindow.setTitle(
      activeApproval ? approvalTitle(activeApproval.approval_kind) : "Xiic SSH 审批",
    );
  }, [activeApproval?.approval_kind]);

  useEffect(() => {
    if (!isTauri()) {
      return;
    }
    const loadApproval = async () => {
      try {
        const current = await invoke<ApprovalRequestedEvent | null>("get_active_approval");
        if (current) {
          setActiveApproval(current.request);
          setPendingApprovalCount(current.pending_count);
          setCopiedCommand(false);
          setStatus("有高危 SSH 操作等待审批。");
        }
      } catch {
        // ignore detached startup race
      }
    };
    void loadApproval();
  }, []);

  useEffect(() => {
    if (!isTauri()) {
      return;
    }
    const setup = async () => {
      const unlistenRequested = await listen<ApprovalRequestedEvent>("approval-requested", (event) => {
        setActiveApproval(event.payload.request);
        setPendingApprovalCount(event.payload.pending_count);
        setCopiedCommand(false);
        setStatus("有高危 SSH 操作等待审批。");
      });

      const unlistenResolved = await listen<ApprovalResolvedEvent>("approval-resolved", (event) => {
        setPendingApprovalCount(event.payload.pending_count);
        setActiveApproval((current) =>
          current?.request_id === event.payload.request_id ? null : current,
        );
        setStatus(event.payload.accepted ? "已允许执行该操作。" : "已拒绝执行该操作。");
      });

      return () => {
        unlistenRequested();
        unlistenResolved();
      };
    };

    let cleanup: (() => void) | undefined;
    setup().then((fn) => { cleanup = fn; });
    return () => { cleanup?.(); };
  }, []);

  async function resolveApproval(accepted: boolean) {
    if (!activeApproval) {
      return;
    }

    setResolvingApproval(true);
    try {
      await invoke("resolve_approval", {
        requestId: activeApproval.request_id,
        accepted,
      });
      setStatus(accepted ? "已允许执行该操作。" : "已拒绝执行该操作。");
    } catch (error) {
      setStatus(asMessage(error));
    } finally {
      setResolvingApproval(false);
    }
  }

  async function copyCommand(command: string) {
    try {
      await navigator.clipboard.writeText(command);
      setCopiedCommand(true);
      window.setTimeout(() => setCopiedCommand(false), 1600);
    } catch {
      setStatus("命令复制失败，请手动选择复制。");
    }
  }

  return (
    <div className="approval-standalone-shell">
      {activeApproval ? (
        <section aria-label="SSH 操作审批" className="approval-panel">
          <div className="approval-panel-header">
            <span className="approval-header-icon" aria-hidden="true">
              <ShieldAlert size={18} />
            </span>
            <div className="approval-header-copy">
              <div className="approval-title-row">
                <h1>{approvalTitle(activeApproval.approval_kind)}</h1>
                <span className="approval-risk-badge">
                  {activeApproval.approval_kind === "high_risk" ? "高危规则" : "需要确认"}
                </span>
              </div>
              <p>{approvalSubtitle(activeApproval.approval_kind, pendingApprovalCount)}</p>
            </div>
          </div>

          <div className="approval-panel-summary">
            <div className="approval-context-grid">
              <ApprovalContextField
                icon={<Server size={14} />}
                label="连接"
                value={activeApproval.metadata.instance_id ?? "-"}
              />
              <ApprovalContextField
                icon={<Terminal size={14} />}
                label="操作"
                value={approvalToolName(activeApproval.metadata.tool_name)}
              />
            </div>
            {activeApproval.metadata.command ? (
              <ApprovalCommandField
                copied={copiedCommand}
                onCopy={() => void copyCommand(activeApproval.metadata.command ?? "")}
                value={activeApproval.metadata.command}
              />
            ) : null}
            {activeApproval.metadata.local_path ? (
              <ApprovalField
                icon={<FileText size={14} />}
                label="本地路径"
                mono
                value={activeApproval.metadata.local_path}
              />
            ) : null}
            {activeApproval.metadata.remote_path ? (
              <ApprovalField
                icon={<FileText size={14} />}
                label="远端路径"
                mono
                value={activeApproval.metadata.remote_path}
              />
            ) : null}
            {activeApproval.metadata.overwrite !== null ? (
              <ApprovalField label="覆盖文件" value={activeApproval.metadata.overwrite ? "是" : "否"} />
            ) : null}
          </div>

          <div className="approval-panel-actions">
            <button
              className="secondary-button approval-deny-button"
              disabled={resolvingApproval}
              onClick={() => void resolveApproval(false)}
              type="button"
            >
              <X size={15} />
              拒绝
            </button>
            <button
              className="primary-button approval-allow-button"
              disabled={resolvingApproval}
              onClick={() => void resolveApproval(true)}
              type="button"
            >
              <Check size={15} />
              允许执行
            </button>
          </div>
        </section>
      ) : (
        <div className="approval-idle-shell">
          <div className="approval-idle-card">
            <span className="approval-idle-icon"><Clock3 size={18} /></span>
            <strong>等待操作审批</strong>
            <span>{status}</span>
          </div>
        </div>
      )}
    </div>
  );
}

function ApprovalField({
  label,
  value,
  mono = false,
  icon,
}: {
  label: string;
  value: string;
  mono?: boolean;
  icon?: ReactNode;
}) {
  return (
    <div className="approval-field">
      <span className="approval-field-label">{icon}{label}</span>
      <strong className={mono ? "mono-value" : ""}>{value}</strong>
    </div>
  );
}

function ApprovalContextField({
  icon,
  label,
  value,
}: {
  icon: ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="approval-context-field">
      <span>{icon}{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ApprovalCommandField({
  copied,
  onCopy,
  value,
}: {
  copied: boolean;
  onCopy: () => void;
  value: string;
}) {
  const lineCount = Math.max(1, value.split("\n").length);
  const rows = Math.min(lineCount, 6);

  return (
    <div className="approval-command-field">
      <div className="approval-command-label">
        <span>将执行的命令</span>
        <button
          aria-label={copied ? "已复制命令" : "复制命令"}
          className="approval-copy-button"
          onClick={onCopy}
          title={copied ? "已复制" : "复制命令"}
          type="button"
        >
          {copied ? <CheckCheck size={14} /> : <Copy size={14} />}
        </button>
      </div>
      <div className="approval-command-shell">
        <textarea
          className="approval-command-code"
          readOnly
          rows={rows}
          spellCheck={false}
          wrap="off"
          value={value}
        />
      </div>
    </div>
  );
}

function approvalToolName(toolName: string): string {
  switch (toolName) {
    case "execute_command":
      return "执行命令";
    case "upload_file":
      return "上传文件";
    case "download_file":
      return "下载文件";
    case "upload_local_file":
      return "上传本地文件";
    case "download_to_local":
      return "下载到本地";
    case "create_session":
      return "创建会话";
    case "close_session":
      return "关闭会话";
    case "sudo":
      return "sudo 命令";
    default:
      return toolName;
  }
}

function approvalTitle(kind: ApprovalRequest["approval_kind"]): string {
  return kind === "high_risk" ? "高危操作" : "操作审批";
}

function approvalSubtitle(
  kind: ApprovalRequest["approval_kind"],
  pendingCount: number,
): string {
  if (kind === "high_risk") {
    return pendingCount > 0
      ? `当前请求处理后还有 ${pendingCount} 个待审批`
      : "请核对目标和操作内容";
  }
  return pendingCount > 0
    ? `后面还有 ${pendingCount} 个待审批请求`
    : "请确认是否执行此操作";
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
