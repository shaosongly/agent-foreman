# Local CMUX Codex Dashboard

这份文档记录当前 fork 里针对本机 Codex + CMUX 工作流做的改造，以及日常使用方式。原项目仍然保留对 Claude、Droid、远程主机和 tmux/stdin 的支持；这里描述的是我们当前优先使用的一期方案。

## 目标

一期目标是把 Mac 上由 CMUX 启动的 Codex 会话集中显示出来：

- 看到当前打开的 Codex Agent。
- 看到每个 Agent 的状态：运行中、空闲、等待回话、Review/审批。
- 看到最近会话内容和待处理提示。
- 从页面给对应 CMUX surface 发送简短消息。
- 过滤掉我们不关心的辅助进程。

目前不把 app-server / LarkBot 当作 Agent 卡片管理；这类长期服务适合放到二期的 Services 模块。Sub Agent / reviewer / guardian 的树状管理也暂不展开，后续作为三期增强。

## 本 fork 的主要改造

### CMUX 发送模式

新增 `send_mode: "cmux"`。本机 Agent 进程里如果带有：

- `CMUX_WORKSPACE_ID`
- `CMUX_SURFACE_ID`

dashboard 会认为它可以交互，并在发话时调用：

```bash
cmux send --workspace <workspace_id> --surface <surface_id> <message>
cmux send-key --workspace <workspace_id> --surface <surface_id> Enter
```

这让我们不依赖 tmux，也不需要安装 tmux。

### Codex 主会话识别

Codex 进程会优先从 CMUX 的进程视图里读取 `workspace:<id>:tag:codex.<session_id>`，把 session id 绑定到真实的 CMUX surface 进程 PID。拿不到 CMUX tag 时，再从命令行里的 `codex resume <session_id>` 提取 session id，最后才考虑非 CMUX 场景下的 cwd/start time 兜底匹配。

对本机 CMUX Codex 来说，如果没有可靠的 session id，就不会仅凭 cwd/start time 猜测 session。这样多个 Codex 都在同一个目录下运行时，宁可只显示进程状态，也避免把某个 surface 的会话内容贴到另一个 Agent 卡片上。

### 辅助进程过滤

以下进程不会作为 Agent 卡片显示：

- `Codex Computer Use` / `SkyComputerUseClient`
- `node_repl`
- `codex app-server`
- `cmux hooks feed --source codex ...`

`codex-auto-review` 不再被全局过滤。如果它是某个 CMUX surface 当前前台的 Codex 进程，会作为一个 `approval_review` 会话显示出来。这符合当前使用方式：有时候“知识库构建”这个工作区前台就是 Review/审批会话，它仍然是用户需要关注的 Agent 状态。

### 状态和内容解析

Codex session 解析增加了这些字段：

- `session_kind`: `main` / `approval_review` / `subagent`
- `needs_user`: 最近输出看起来需要用户回复
- `has_result`: Agent 已经输出 final answer，等待用户查看

页面会把 `needs_user` 或 `has_result` 显示到“等回话”状态中。

### CMUX 工作区名称

本地模式会读取：

```bash
cmux list-workspaces --id-format both
```

如果能匹配到 workspace id，卡片标题会优先显示 CMUX workspace 名称，例如“知识库构建”“IOS开发”，而不是只显示目录名。

### Markdown 渲染

最近输出从纯文本 `<pre>` 改成安全的 Markdown 子集渲染。当前支持：

- 标题
- 段落
- 无序列表
- 行内代码
- 粗体、斜体
- fenced code block

渲染前会先转义 HTML，避免把 Agent 输出当作可执行 HTML 插入页面。

## 安装和启动

推荐使用 venv 隔离依赖：

```bash
cd /Users/sentropsy/ss_playground/agent-foreman
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp config.local-cmux.example.json config.json
.venv/bin/python monitor_server.py --host 127.0.0.1 --port 8787
```

也可以直接使用脚本：

```bash
cd /Users/sentropsy/ss_playground/agent-foreman
./run-local-cmux.sh
```

打开：

```text
http://127.0.0.1:8787
```

## 配置

本机 CMUX 推荐配置：

```json
{
  "send_mode": "cmux",
  "dashboard": {
    "agent_types": ["codex"],
    "hide_empty_tools": true
  },
  "hosts": [
    {
      "name": "local",
      "mode": "local",
      "send_mode": "cmux"
    }
  ],
  "paths": {
    "codex_sessions": "~/.codex/sessions"
  }
}
```

`dashboard.agent_types` 控制页面默认展示哪些工具类型。当前本机 CMUX 工作流建议只放 `codex`。如果后续要重新显示 Claude 或 Droid，可以改成：

```json
{
  "dashboard": {
    "agent_types": ["codex", "claude", "droid"],
    "hide_empty_tools": true
  }
}
```

页面顶部也会提供工具类型 chip，用来临时开关当前浏览器里的展示状态；这个临时选择会保存在浏览器 `localStorage` 里。

`config.json` 被 `.gitignore` 忽略，可以按本机情况修改。

## 日常使用

1. 在 CMUX 的不同 workspace 里启动或恢复 Codex。
2. 启动 dashboard。
3. 页面会按 Agent 类型和状态分组展示。
4. 卡片里的“最近动静”显示最近会话内容。
5. 卡片里的“还没干完”显示待处理提示。
6. 可以在输入框里发消息，也可以点快捷按钮：
   - `继续`
   - `收到`
   - `请总结当前状态`

## 当前边界

- 现在的目标是“前台 Agent 级别”的管理，不展开 Sub Agent 树。
- app-server / LarkBot 暂不显示为 Agent 卡片。
- Markdown 渲染是轻量子集，不追求完整 GitHub Flavored Markdown。
- 远程主机仍走原项目逻辑；CMUX 模式只支持本机。

## 建议后续优化

- 用 launchd 做登录自动启动。
- 增加页面级筛选：只看 Codex、只看等待回话、只看当前 CMUX window。
- 给 `needs-input` 增加系统通知或声音提醒。
- 把 Services 模块单独做出来，用来管理 app-server / LarkBot。
- 三期再做主 Agent 与 Sub Agent 的层级展示。
