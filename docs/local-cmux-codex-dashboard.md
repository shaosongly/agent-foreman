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

Codex 进程会优先从 CMUX 的进程视图里读取 `workspace:<id>:tag:codex.<session_id>`，把 session id 绑定到真实的 CMUX surface 进程 PID。实现上会合并 `cmux top` 里同一 PID 的 tag / surface 行，并沿父进程链继承上下文，所以 `surface -> login -> shell -> codex` 这种结构也能拿到所属 workspace、surface 和 session。

自动匹配优先级是：

1. `session_overrides` 手动覆盖。
2. CMUX tag：`workspace:<id>:tag:codex.<session_id>`。
3. 命令行：`codex resume <session_id>`。
4. 主动探测后保存的 `session_bindings`。
5. CMUX Codex 的唯一 cwd 候选兜底。
6. 非 CMUX 场景下的 cwd/start time 兜底匹配。

对本机 CMUX Codex 来说，如果没有可靠的 session id，只会在同一个 cwd 下只有一个可用 session 候选时自动兜底。多个 Codex 都在同一个目录下运行时，会标成候选不唯一，宁可只显示进程状态，也避免把某个 surface 的会话内容贴到另一个 Agent 卡片上。

卡片的“监工细节”会显示匹配来源：

- `手动覆盖`
- `主动探测`
- `CMUX tag`
- `resume 命令`
- `目录唯一`
- `目录/时间`
- `候选不唯一`
- `未匹配`

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
  "session_bindings_file": "session_bindings.json",
  "probe_timeout_sec": 20,
  "probe_message_template": "请只回复：{token}",
  "session_overrides": {},
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

### 主动探测匹配

如果某个 Codex 卡片没有可靠匹配到 session，或者你觉得它显示的最近内容不对，可以点卡片上的 `重新识别`。它会对这个 CMUX surface 发送一条短消息：

```text
请只回复：AF-PROBE-XXXXXX
```

然后 dashboard 会在最近的 Codex session 文件里查找这个唯一 token。找到后会把当前 CMUX surface 和 session id 写入 `session_bindings.json`，后续刷新页面或重启 dashboard 都可以复用这个绑定。

这个动作有轻微侵入性，因为它会在 Codex 会话里插入一条探测消息。它是显式按钮，不会默认自动对所有 Agent 执行。发送目标仍然永远以 CMUX workspace/surface 为准，探测绑定只影响卡片展示哪个 session 内容。

### 手动覆盖匹配

如果自动识别仍然把某个 CMUX 工位匹配错了，可以在本机 `config.json` 里加 `session_overrides`。它只影响明确写入的条目，不会关闭其他 Agent 的自动匹配。

```json
{
  "session_overrides": {
    "cmux_workspace_name:知识库构建": {
      "session_id": "019e3015-671b-7ec2-a133-1cf4a7b77c99",
      "alias": "知识库构建"
    },
    "cmux_workspace:F3A4C221-2C13-4166-AAB1-A242861C4F99": {
      "session_id": "019e30e1-4343-7c11-a58e-c95df56f4fe2"
    },
    "cmux_surface:surface:2": "019e30e1-4343-7c11-a58e-c95df56f4fe2",
    "pid:28760": "019e30e1-4343-7c11-a58e-c95df56f4fe2"
  }
}
```

建议优先用 `cmux_workspace_name:<名称>` 或 `cmux_workspace:<UUID>`。`cmux_surface:surface:<编号>` 和 `pid:<pid>` 更适合临时排查，因为 CMUX surface 编号和进程 PID 可能会随重启变化。

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
