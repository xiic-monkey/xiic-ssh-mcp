# Xiic SSH MCP

通过 MCP（Model Context Protocol）让 AI 编码助手安全地操作远程服务器。

## 它做什么

Xiic SSH MCP 是一个本地 MCP 服务器，为 Cursor、Claude Desktop 等 AI 工具提供 SSH 能力——创建会话、执行命令、上传下载文件。所有操作经过白名单过滤和人工审批，确保 AI 只能做你允许的事。

## 架构

项目由三个组件构成：

| 组件 | 产物 | 职责 |
|------|------|------|
| MCP 核心库 | `xiic-ssh-mcp` | STDIO MCP 服务器，SSH 会话管理，白名单检查，审批调度 |
| 桌面管理应用 | `xiic-ssh-manager-desktop` | 可视化管理连接、查看日志、配置 MCP、系统设置 |
| 审批应用 | `xiic-ssh-approval` | 弹窗审批高危 SSH 操作 |

前端共享 `web/` 目录，通过 `index.html` 和 `approval.html` 分别加载管理界面和审批界面。

## MCP 工具

| 工具 | 说明 |
|------|------|
| `list_servers` | 列出所有已配置的 SSH 连接 |
| `create_session` | 建立新的 SSH 会话 |
| `execute_command` | 在会话中执行远程命令 |
| `upload_file` | 通过 SFTP 上传文件 |
| `download_file` | 通过 SFTP 下载文件 |

## 安全机制

### 白名单

白名单按四个维度匹配操作：**工具名**、**命令**、**路径**、**实例**。支持 glob 模式。

- 所有维度都被 Allow 规则覆盖 → 直接放行
- 命中 Deny 规则 → 直接拒绝
- 部分维度未覆盖 → 进入审批流程

### 审批

当操作未被白名单放行时，进入审批流程。支持两种审批方式：

- **Elicitation 模式**：通过 MCP 协议让 AI 客户端自身弹出审批（客户端需支持 elicitation 能力）
- **Local 模式**：弹出独立的审批窗口（Tauri 应用），或使用系统原生弹窗

审批模式由 `--approval-mode` 参数控制：
- `auto`（默认）：客户端支持 elicitation 则用 elicitation，否则用 local
- `elicitation`：强制 elicitation
- `local`：强制本地审批

设置中的「使用系统弹窗进行审核」开关可让 local 模式直接调用系统原生对话框（macOS AppleScript / Windows PowerShell / Linux zenity），跳过审批 App。

### 凭据存储

SSH 密码和私钥通过操作系统 Keychain 安全存储，私钥仅驻留内存、不落盘。

## 安装

### 从源码构建

```bash
./install.sh
```

需要 `cargo` 和 `npm`。构建完成后三个二进制安装到 `~/.local/bin/`：

```
~/.local/bin/xiic-ssh-manager-desktop
~/.local/bin/xiic-ssh-approval
~/.local/bin/xiic-ssh-mcp
```

可选参数：

```bash
./install.sh --root /usr/local    # 指定安装目录
./install.sh --debug              # 构建 debug 版本
```

### 从 GitHub Releases 安装

```bash
curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/install.sh | bash -s -- --repo <owner>/<repo>
```

## 配置 AI 客户端

1. 启动桌面管理应用 `xiic-ssh-manager-desktop`
2. 添加 SSH 连接
3. 在应用内复制 MCP JSON 配置
4. 粘贴到 AI 客户端的 MCP 服务器配置中

配置示例：

```json
{
  "mcpServers": {
    "xiic-ssh": {
      "command": "/path/to/xiic-ssh-mcp",
      "args": [
        "--db-path", "~/Library/Application Support/com.xiic.sshmanager/instances.sqlite3",
        "--keyring-service", "com.xiic.ssh-manager",
        "--notify-socket", "~/Library/Application Support/com.xiic.sshmanager/notify.sock",
        "--approval-mode", "auto",
        "--approval-endpoint", "~/Library/Application Support/com.xiic.sshmanager/approval.sock"
      ],
      "env": {
        "SSH_ASKPASS_REQUIRE": "never"
      }
    }
  }
}
```

## 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--db-path <path>` | SQLite 数据库路径 | 必选 |
| `--keyring-service <name>` | Keychain 服务名 | `com.xiic.ssh-manager` |
| `--notify-socket <path>` | 日志通知 IPC 端点 | 无 |
| `--whitelist <strict\|off>` | 白名单模式 | `strict` |
| `--approval-mode <auto\|elicitation\|local>` | 审批模式 | `auto` |
| `--approval-endpoint <path>` | 审批 IPC 端点 | 无 |

## 开发

```bash
# 安装前端依赖
npm install

# 启动 Vite 开发服务器
npx vite --port 1430

# 构建 MCP 核心库
cargo build

# 构建桌面管理应用
cargo build --manifest-path src-tauri/Cargo.toml

# 构建审批应用
cargo build --manifest-path approval-tauri/Cargo.toml

# 构建 + 启动桌面管理应用（开发模式）
cargo build --manifest-path src-tauri/Cargo.toml && ./src-tauri/target/debug/xiic-ssh-manager-desktop
```

## 技术栈

- **Rust** — 后端核心，SSH 会话管理，MCP 协议实现
- **Tauri** — 桌面应用框架（管理应用 + 审批应用）
- **React + TypeScript** — 前端界面
- **SQLite** — 连接配置、白名单规则、操作日志持久化
- **ssh2** — SSH/SFTP 协议实现（vendored-openssl）
- **keyring** — 操作系统 Keychain 凭据存储
