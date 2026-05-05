# xiic-ssh-mcp

一个本地桌面 SSH 连接管理器，同时对外暴露 MCP 接口。

这版实现不做终端模拟器。核心目标是：

- 可视化管理 SSH 连接
- 新增、修改、删除连接
- 保存前支持测试连接
- 本地持久化连接配置
- 对 agent 暴露 4 个 MCP 工具
- 一键复制 HTTP / SSE 两种 MCP JSON 配置

## 先说清楚：没有软件账号登录

这个软件没有自己的登录系统，没有“平台账号密码”。

你在界面里看到的：

- `SSH target`
- `SSH password`
- `SSH private key`

这些都是远程服务器的 SSH 凭据，不是这个软件的登录密码。

例如你平时在终端里这样连：

```bash
ssh root@192.168.1.20
```

那这里的：

- `username` 就是 `root`
- `host` 就是 `192.168.1.20`
- `SSH password` 就是这台远程机器上 `root` 用户的登录密码

如果 macOS 弹出系统密码窗口，那也不是这个软件在登录，而是：

- 系统钥匙串 `Keychain`
- 在请求授权保存或读取 SSH 密钥 / SSH 密码

## 更自然的填写方式

UI 已经支持直接填 SSH 目标地址。

你可以在 `SSH target` 输入这些格式：

```text
ssh://root@192.168.1.20:22
root@192.168.1.20:22
root@192.168.1.20
192.168.1.20
```

点 `Parse` 后会自动填充：

- `username`
- `host`
- `port`

然后你再单独补：

- `SSH password`
  或
- `SSH private key`

密码本来就不应该从 URL 里自动带出来，所以它仍然要单独填。

## 当前能力

桌面应用提供：

- 连接列表
- 新建连接
- 编辑连接
- 删除连接
- 测试连接
- 一键复制 STDIO MCP 配置

MCP 工具保持为：

- `create_session`
- `execute_command`
- `upload_file`
- `download_file`

## 产品形态

这是一个本地单用户桌面应用：

- UI：`Tauri v2 + React + TypeScript + Vite`
- 核心逻辑：`Rust`
- SSH / SFTP：`ssh2`
- 元数据存储：`SQLite`
- 密码 / 私钥存储：系统钥匙串 `keyring`
- MCP 接入：`stdio`

## 安装

### GitHub Release 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/install.sh | bash -s -- --repo <owner>/<repo>
```

如果你在发布前已经把 `install.sh` 里的 `DEFAULT_GITHUB_REPOSITORY` 写成真实仓库，用户可以直接：

```bash
curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/install.sh | bash
```

默认会安装到：

```bash
~/.local/bin/xiic-ssh-manager-desktop
~/.local/bin/xiic-ssh-mcp
```

安装完成后直接运行：

```bash
~/.local/bin/xiic-ssh-manager-desktop
```

### 本地源码安装

```bash
./install.sh
```

源码安装会自动执行：

- `npm install`（如果 `node_modules` 不存在）
- `npm run build`
- `cargo build --manifest-path src-tauri/Cargo.toml --release`

然后把桌面可执行文件复制到：

```bash
~/.local/bin/xiic-ssh-manager-desktop
~/.local/bin/xiic-ssh-mcp
```

## GitHub Release 产物命名

`install.sh` 期望你的 Release 里有这些桌面二进制压缩包：

- `xiic-ssh-manager-desktop-x86_64-unknown-linux-gnu.tar.gz`
- `xiic-ssh-manager-desktop-aarch64-unknown-linux-gnu.tar.gz`
- `xiic-ssh-manager-desktop-x86_64-apple-darwin.tar.gz`
- `xiic-ssh-manager-desktop-aarch64-apple-darwin.tar.gz`

每个压缩包里至少包含两个可执行文件：

```text
xiic-ssh-manager-desktop
xiic-ssh-mcp
```

## 工作原理

### 连接管理

连接信息分两层保存：

- 非敏感信息写入 SQLite
  - `instance_id`
  - `name`
  - `host`
  - `port`
  - `username`
  - `auth_kind`
  - `host_key_check`
  - `notes`
- 敏感信息写入系统钥匙串
  - `password`
  - `private_key`
  - `passphrase`

### 测试连接

UI 里的“测试连接”不会创建 MCP 会话。它只会：

1. 使用当前表单内容建立一次真实 SSH 连接
2. 完成认证
3. 返回成功或失败消息

这样可以在保存前就验证配置是否可用。

### MCP 会话

agent 调用 MCP 时：

1. 先用 `create_session` 传入 `instance_id`
2. `stdio` helper 读取 SQLite 元数据和钥匙串凭据
3. 建立真实 SSH 连接并返回 `session_id`
4. 后续通过 `session_id` 调用命令执行、上传、下载

注意：

- `session_id` 只保存在当前进程内
- 应用重启后旧会话全部失效
- 当前不做自动重连

## MCP 配置复制

桌面 UI 会直接生成并复制一份 `stdio` JSON 片段。

### STDIO 示例

```json
{
  "mcpServers": {
    "xiic-ssh": {
      "command": "/Users/you/.local/bin/xiic-ssh-mcp",
      "args": [
        "--db-path",
        "/Users/you/Library/Application Support/com.xiic.sshmanager/instances.sqlite3",
        "--keyring-service",
        "com.xiic.ssh-manager"
      ]
    }
  }
}
```

## MCP 工具说明

### `create_session`

输入：

```json
{
  "instance_id": "prod-server"
}
```

### `execute_command`

输入：

```json
{
  "session_id": "uuid",
  "command": "uname -a",
  "command_description": "确认远程服务器的内核和系统信息",
  "timeout_secs": 30
}
```

说明：

- `command_description` 为必填字段，用于审批弹窗说明这条命令的目的
- 该说明也会写入操作日志，便于后续回看

### `upload_file`

输入：

```json
{
  "session_id": "uuid",
  "remote_path": "/tmp/demo.txt",
  "content": "hello world",
  "encoding": "utf8",
  "overwrite": true
}
```

### `download_file`

输入：

```json
{
  "session_id": "uuid",
  "remote_path": "/tmp/demo.txt",
  "encoding": "utf8"
}
```

说明：

- 上传支持 `utf8` / `base64`
- 下载支持 `utf8` / `base64`
- 下载默认返回 `base64`
- 不支持交互式 shell

## 本地开发

### 安装依赖

```bash
npm install
```

### 启动桌面开发模式

```bash
npm run tauri:dev
```

### 构建前端

```bash
npm run build
```

### 检查桌面 Rust 侧

```bash
cargo check --manifest-path src-tauri/Cargo.toml
```

### 检查核心 Rust 侧

```bash
cargo test
```

## 目录结构

- `web/`
  React 前端
- `src-tauri/`
  Tauri 桌面应用入口
- `src/app_core.rs`
  SQLite、钥匙串、SSH 会话、连接测试
- `src/mcp.rs`
  `stdio` MCP helper
- `src/storage.rs`
  SQLite 持久化
- `src/credentials.rs`
  系统钥匙串读写

## 当前限制

- 只支持本地单用户
- 不支持终端界面
- 不支持端口转发
- 不支持目录级同步
- 不支持自动重连
- 不支持多人共享同一个配置中心

## 验证状态

当前仓库已通过这些本地检查：

- `cargo check`
- `cargo check --manifest-path src-tauri/Cargo.toml`
- `cargo test`
- `npm exec tsc --noEmit`
- `npm run build`
