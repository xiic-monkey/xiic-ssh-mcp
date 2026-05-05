# xiic-ssh-mcp

一个本地桌面 SSH 连接管理器，用来可视化维护远程服务器连接，并把这些连接安全地暴露给支持 MCP 的 agent 使用。

这一版不做终端模拟器：它不是一个新的 Terminal，而是一个本地 SSH 连接配置中心 + MCP 桥接工具。

## 主要功能

- 可视化管理 SSH 连接
- 新增、修改、删除连接配置
- 保存前测试 SSH 连接是否可用
- 本地持久化连接配置
- 使用系统钥匙串保存 SSH 密码、私钥和私钥口令
- 对 agent 暴露 4 个 MCP 工具
- 一键复制 MCP JSON 配置
- 独立审批应用处理高危 SSH 操作

## 没有软件账号登录

这个软件没有自己的登录系统，也没有“平台账号密码”。

界面里的这些字段：

- `SSH target`
- `SSH password`
- `SSH private key`
- `passphrase`

都指向远程服务器的 SSH 凭据，不是这个软件的登录密码。

例如你平时在终端里这样连接服务器：

```bash
ssh root@192.168.1.20
```

那在软件里：

- `username` 填 `root`
- `host` 填 `192.168.1.20`
- `SSH password` 填这台远程机器上 `root` 用户的 SSH 登录密码

如果 macOS 弹出系统密码窗口，那也不是软件账号登录，而是系统钥匙串 `Keychain` 在请求授权，用于保存或读取 SSH 密码、SSH 私钥等敏感信息。

## SSH Target 填写方式

你可以直接在 `SSH target` 输入常见 SSH 地址格式：

```text
ssh://root@192.168.1.20:22
root@192.168.1.20:22
root@192.168.1.20
192.168.1.20
```

点击 `Parse` 后会自动填充：

- `username`
- `host`
- `port`

然后再单独填写认证信息：

- `SSH password`，或
- `SSH private key`

密码和私钥不会从 URL 里自动提取，需要单独填写。

## 连接管理

每个 SSH 连接配置包含：

- `instance_id`：给 agent 使用的连接标识
- `name`：界面展示名称
- `host` / `port`：远程服务器地址和端口
- `username`：远程服务器 SSH 用户名
- `auth_kind`：密码或私钥认证
- `host_key_check`：是否检查主机密钥
- `notes`：备注

保存前可以点击测试连接。测试连接会使用当前表单内容发起一次真实 SSH 认证，并返回成功或失败原因。

## 本地数据保存

连接数据分两类保存：

- 非敏感信息保存在本地 SQLite
- 敏感信息保存在系统钥匙串

敏感信息包括：

- SSH 密码
- SSH 私钥
- 私钥口令

这些数据只保存在本机，不需要上传到任何平台账号。

## 审批工作方式

高危 SSH 操作不会在主界面里弹一层网页风 overlay，也不会强行把主窗口带到前台。

这一版改成了独立审批进程：

- `xiic-ssh-manager-desktop`：管理连接、查看日志、复制 MCP 配置
- `xiic-ssh-approval`：只负责接收审批请求、弹出审批小窗、允许或拒绝
- `xiic-ssh-mcp`：给 agent 提供 MCP stdio 服务

执行链路是：

1. agent 通过 `xiic-ssh-mcp` 调用 SSH 工具
2. 命中需要审批的高危操作
3. helper 优先连接本地审批通道
4. 如果审批应用未启动，helper 自动拉起 `xiic-ssh-approval`
5. 用户在独立审批窗里点击允许或拒绝
6. helper 再继续执行或拒绝这次工具调用

如果当前环境没有可用的独立审批 UI，helper 会回退到系统原生确认窗，不会再弹一个空白的大白窗。

## MCP 工具

软件对 agent 暴露 4 个 MCP 工具：

- `create_session`：根据 `instance_id` 创建 SSH 会话
- `execute_command`：在远程服务器执行命令
- `upload_file`：上传文件内容到远程服务器
- `download_file`：从远程服务器下载文件内容

典型调用流程：

1. agent 调用 `create_session` 创建会话
2. 返回 `session_id`
3. agent 使用 `session_id` 执行命令、上传文件或下载文件

`session_id` 只在当前 MCP 进程内有效。应用或 MCP 进程重启后，需要重新创建会话。

## MCP 配置

桌面界面会生成可直接复制的 MCP JSON 配置。复制后粘贴到支持 MCP 的客户端配置里即可使用。

当前本地 helper 使用 `stdio` 方式启动 MCP server，配置形态类似：

```json
{
  "mcpServers": {
    "xiic-ssh": {
      "command": "/Users/you/.local/bin/xiic-ssh-mcp",
      "args": [
        "--db-path",
        "/Users/you/Library/Application Support/com.xiic.sshmanager/instances.sqlite3",
        "--keyring-service",
        "com.xiic.ssh-manager",
        "--notify-socket",
        "/Users/you/Library/Application Support/com.xiic.sshmanager/notify.sock",
        "--approval-mode",
        "auto",
        "--approval-endpoint",
        "/Users/you/Library/Application Support/com.xiic.sshmanager/approval.sock"
      ],
      "env": {
        "HOME": "/Users/you",
        "SSH_ASKPASS_REQUIRE": "never"
      }
    }
  }
}
```

请优先使用界面里复制出来的配置，因为里面会包含当前机器上的实际路径。

配置里的 `--approval-endpoint` 由桌面应用自动生成，用来让 helper 和独立审批应用通信。这个字段不需要手动改。

## 工具参数示例

### create_session

```json
{
  "instance_id": "prod-server"
}
```

### execute_command

```json
{
  "session_id": "uuid",
  "command": "uname -a",
  "timeout_secs": 30
}
```

### upload_file

```json
{
  "session_id": "uuid",
  "remote_path": "/tmp/demo.txt",
  "content": "hello world",
  "encoding": "utf8",
  "overwrite": true
}
```

### download_file

```json
{
  "session_id": "uuid",
  "remote_path": "/tmp/demo.txt",
  "encoding": "utf8"
}
```

上传和下载支持：

- `utf8`
- `base64`

## 安装与运行

### 本地开发

安装依赖：

```bash
npm install
```

启动桌面开发模式：

```bash
npm run tauri:dev
```

启动独立审批开发模式：

```bash
npm run approval:dev
```

如果你只启动了主界面开发模式，没有构建或启动审批应用，helper 在开发态会直接回退系统原生审批窗，避免再出现白屏审批窗口。

构建前端：

```bash
npm run build
```

检查 Rust 代码：

```bash
cargo check
cargo check --manifest-path src-tauri/Cargo.toml
cargo check --manifest-path approval-tauri/Cargo.toml
```

### 本地安装

```bash
./install.sh
```

默认安装到：

```text
~/.local/bin/xiic-ssh-manager-desktop
~/.local/bin/xiic-ssh-approval
~/.local/bin/xiic-ssh-mcp
```

启动桌面应用：

```bash
~/.local/bin/xiic-ssh-manager-desktop
```

审批应用通常不需要手动启动。发生高危操作审批时，helper 会自动拉起：

```bash
~/.local/bin/xiic-ssh-approval
```

## 技术栈

- 桌面应用：`Tauri v2`
- 前端：`React`、`TypeScript`、`Vite`
- 核心逻辑：`Rust`
- SSH / SFTP：`ssh2`
- 本地数据库：`SQLite`
- 凭据存储：系统钥匙串 `keyring`
- MCP helper：`stdio`

## 当前限制

- 不提供终端模拟器
- 不支持交互式 shell
- 不支持端口转发
- 不支持目录级同步
- 不支持自动重连
- 不提供多人共享配置中心
- 开发态下如果独立审批前端未就绪，会回退系统原生审批窗
