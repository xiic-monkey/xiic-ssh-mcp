import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

type ApprovalOperationMetadata = {
  tool_name: string;
  command: string | null;
  remote_path: string | null;
  instance_id: string | null;
};

type ApprovalRequest = {
  kind: string;
  request_id: string;
  message: string;
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

export default function ApprovalApp() {
  const [activeApproval, setActiveApproval] = useState<ApprovalRequest | null>(null);
  const [pendingApprovalCount, setPendingApprovalCount] = useState(0);
  const [resolvingApproval, setResolvingApproval] = useState(false);
  const [status, setStatus] = useState("等待审批请求…");

  useEffect(() => {
    const loadApproval = async () => {
      try {
        const current = await invoke<ApprovalRequestedEvent | null>("get_active_approval");
        if (current) {
          setActiveApproval(current.request);
          setPendingApprovalCount(current.pending_count);
          setStatus("有高危 SSH 操作等待审批。");
        }
      } catch {
        // ignore detached startup race
      }
    };
    void loadApproval();
  }, []);

  useEffect(() => {
    const setup = async () => {
      const unlistenRequested = await listen<ApprovalRequestedEvent>("approval-requested", (event) => {
        setActiveApproval(event.payload.request);
        setPendingApprovalCount(event.payload.pending_count);
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

  return (
    <div className="approval-standalone-shell">
      {activeApproval ? (
        <section aria-label="SSH 操作审批" className="approval-panel">
          <div className="approval-panel-header">
            <div className="approval-dot" aria-hidden="true" />
            <div>
              <h1>操作审批</h1>
              <p>{pendingApprovalCount > 0 ? `后面还有 ${pendingApprovalCount} 个待审批请求` : "请确认是否执行此操作"}</p>
            </div>
          </div>

          <div className="approval-panel-summary">
            <ApprovalField label="工具" value={approvalToolName(activeApproval.metadata.tool_name)} />
            <ApprovalField label="连接" value={activeApproval.metadata.instance_id ?? "-"} />
            {activeApproval.metadata.command ? (
              <ApprovalCommandField value={activeApproval.metadata.command} />
            ) : null}
            {activeApproval.metadata.remote_path ? (
              <ApprovalField label="路径" value={activeApproval.metadata.remote_path} mono />
            ) : null}
          </div>

          <div className="approval-panel-actions">
            <button
              className="secondary-button"
              disabled={resolvingApproval}
              onClick={() => void resolveApproval(false)}
              type="button"
            >
              拒绝
            </button>
            <button
              className="primary-button"
              disabled={resolvingApproval}
              onClick={() => void resolveApproval(true)}
              type="button"
            >
              允许执行
            </button>
          </div>
        </section>
      ) : (
        <div className="approval-idle-shell">
          <div className="approval-idle-card">
            <strong>操作审批</strong>
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
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="approval-field">
      <span>{label}</span>
      <strong className={mono ? "mono-value" : ""}>{value}</strong>
    </div>
  );
}

function ApprovalCommandField({ value }: { value: string }) {
  const lineCount = Math.max(1, value.split("\n").length);
  const rows = Math.min(lineCount, 6);

  return (
    <div className="approval-command-field">
      <span>命令</span>
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
    case "create_session":
      return "创建会话";
    default:
      return toolName;
  }
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
