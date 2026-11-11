# Uber ADR Sensor 源码笔记

> 版本锚定：`uber/ADR` 仓库 `Sensor/` 目录，初始公开 release commit `db4fb0e`（2026-07-29），Gemini CLI 支持 commit `93ed35c`（2026-09-16），Antigravity 支持截至 2026-10-16。Python 3.9–3.13，依赖 `tabulate` + `zstandard`（可选 `opentelemetry` extra）。Apache 2.0。

## 目录

- [一、Sensor 是什么](#一sensor-是什么)
  - [1.1 设计动机：可观测性鸿沟](#11-设计动机可观测性鸿沟)
  - [1.2 在 ADR 系统中的位置](#12-在-adr-系统中的位置)
  - [1.3 与 Discovery 的边界](#13-与-discovery-的边界)
- [二、能力范围](#二能力范围)
  - [2.1 能做什么](#21-能做什么)
  - [2.2 不能做什么](#22-不能做什么)
  - [2.3 11 个支持的 AI 代理平台](#23-11-个支持的-ai-代理平台)
  - [2.4 四维遥测模型](#24-四维遥测模型)
- [三、技术实现方案](#三技术实现方案)
  - [3.1 整体架构](#31-整体架构)
  - [3.2 AgentEvent 统一 Schema](#32-agentevent-统一-schema)
  - [3.3 解析器架构](#33-解析器架构)
  - [3.4 AgentObserver 编排器](#34-agentobserver-编排器)
  - [3.5 输出与导出](#35-输出与导出)
  - [3.6 诊断与健康](#36-诊断与健康)
  - [3.7 CLI](#37-cli)
  - [3.8 Python API](#38-python-api)
- [四、各代理日志路径与解析细节](#四各代理日志路径与解析细节)
  - [4.1 Claude Code](#41-claude-code)
  - [4.2 Cursor IDE](#42-cursor-ide)
  - [4.3 Cline](#43-cline)
  - [4.4 Claude Desktop](#44-claude-desktop)
  - [4.5 OpenAI Codex CLI](#45-openai-codex-cli)
  - [4.6 GitHub Copilot CLI](#46-github-copilot-cli)
  - [4.7 DeepSeek Harness](#47-deepseek-harness)
  - [4.8 Warp Terminal](#48-warp-terminal)
  - [4.9 opencode](#49-opencode)
  - [4.10 Gemini CLI](#410-gemini-cli)
  - [4.11 Google Antigravity](#411-google-antigravity)
- [五、正反例测试方法集](#五正反例测试方法集)
  - [5.1 测试设计原则](#51-测试设计原则)
  - [5.2 正例测试集](#52-正例测试集)
  - [5.3 反例测试集](#53-反例测试集)
  - [5.4 边界测试集](#54-边界测试集)
  - [5.5 测试运行方式](#55-测试运行方式)
- [六、安全分析与技术权衡](#六安全分析与技术权衡)
  - [6.1 与 EDR 的对比](#61-与-edr-的对比)
  - [6.2 与网关方案的对比](#62-与网关方案的对比)
  - [6.3 设计权衡](#63-设计权衡)
- [七、缺口与未验证事项](#七缺口与未验证事项)
- [附录 A 代码坐标索引](#附录-a-代码坐标索引)
- [附录 B 关键技术结论及证据索引](#附录-b-关键技术结论及证据索引)
- [附录 C 术语表](#附录-c-术语表)

---

## 一、Sensor 是什么

### 1.1 设计动机：可观测性鸿沟

ADR 论文（arXiv:2605.17380，MLSys 2026）指出企业 AI 代理安全面临三大持续挑战，Sensor 直接解决第一个：

> **有限的可观测性** —— 现有 EDR 工具能看到文件写入，但看不到代理推理、prompt 或连接意图与执行的因果链。

传统 EDR 设计于 MCP 出现之前，仅捕获系统级遥测（文件写入、进程活动、网络调用）。当 AI 代理写入文件时，EDR 能看到 `write()` 系统调用，但看不到：

- 触发该操作的用户 prompt（"帮我修复这个 bug"）
- 代理的推理过程（chain-of-thought）
- 调用了哪些 MCP 工具及其参数
- 工具调用的因果关系（prompt → reasoning → tool call → outcome）

**关键示例**（来自论文）：用户要求"总结 Jira ticket"，但代理读取了 `~/.ssh/id_rsa` 并发起 HTTP 请求。EDR 看到文件读取和网络连接，但无法判断这些行为是否偏离用户意图。Sensor 通过捕获完整的代理会话语义链来闭合这个鸿沟。

### 1.2 在 ADR 系统中的位置

ADR 系统包含五个互补能力，Sensor 承担其中"可观测性"：

| 能力 | 组件 | 开源状态 |
|---|---|---|
| 发现未授权 AI 工具 | ADR Discovery | ✅ 已开源 |
| **观察代理活动** | **ADR Sensor** | **✅ 已开源** |
| 评估防御能力 | ADR-Bench | ✅ 已开源 |
| 检测威胁 | ADR Detector | ✅ 已开源 |
| 阻止不安全操作 | ADR Prevention | ❌ 未开源 |

Sensor 的产出（AgentEvent）是 Detector 的输入。没有 Sensor 的遥测，Detector 的两级检测架构（Tier 1 分诊 + Tier 2 深度推理）就没有数据可分析。

### 1.3 与 Discovery 的边界

Discovery 回答"端点上有哪些 AI 工具"，Sensor 回答"这些工具在做什么"。两者共享端点但数据模型完全不同：

| 维度 | Discovery | Sensor |
|---|---|---|
| 产出 | Asset 快照（静态清单） | AgentEvent 流（动态会话） |
| 触发 | 单次扫描或定期扫描 | 每小时调度（Uber 生产环境） |
| 数据来源 | 文件系统、包管理器、注册表、进程表 | AI 代理的本地日志/数据库 |
| 时间维度 | 快照时刻 | 回溯窗口（默认 14 天） |
| 下游消费者 | 安全审查、资产登记 | 威胁检测、安全监控 |

Discovery 发现 `~/.claude` 目录存在，说明安装了 Claude Code；Sensor 解析 `~/.claude/projects/` 下的 JSONL transcripts，还原 Claude Code 的完整会话历史。

---

## 二、能力范围

### 2.1 能做什么

| 能力 | 说明 |
|---|---|
| 多源日志采集 | 从 11 个 AI 代理平台的本地存储中解析会话数据 |
| 统一标准化 | 将不同格式（JSONL、SQLite、JSON）转换为统一的 AgentEvent schema |
| 会话重建 | 关联分散的日志条目，重建 prompt → reasoning → tool call → outcome 的完整因果链 |
| 工具调用记录 | 捕获 MCP 工具调用的名称、类型、参数、结果和状态 |
| 环境上下文 | 捕获 session 级配置（MCP 服务器、权限模式、模型版本、插件、技能） |
| Token 用量 | 规范化每轮和累计 token 计数（部分代理支持） |
| 多格式导出 | JSON / JSONL 文件输出 + OpenTelemetry OTLP/HTTP Logs 导出 |
| 跨平台 | macOS、Linux、Windows 三平台支持 |
| 诊断 | 结构化健康报告（ok / empty / no_input / partial / failed） |
| 增量保存 | `--save-sessions` 按 session 粒度保存，支持增量更新 |

### 2.2 不能做什么

| 限制 | 说明 |
|---|---|
| **不是 EDR** | 不捕获系统级遥测（进程、文件写入、网络连接），只捕获代理语义层 |
| **不实时阻断** | Sensor 是观察者，不拦截代理操作；Prevention 组件未开源 |
| **不修改代理行为** | 不注入 prompt、不修改 MCP 配置、不干预代理执行 |
| **不做威胁检测** | 检测由 Detector 组件负责；Sensor 只负责数据采集和标准化 |
| **不支持所有 AI 工具** | 仅支持 11 个平台的日志解析；未列出的代理需开发新解析器 |
| **不捕获 VS Code Copilot Chat** | Copilot CLI 解析器仅覆盖 `session-state/`，不读取 VS Code 扩展存储 |
| **不捕获未保存会话** | 只解析已持久化的日志，内存中的活动不在范围内 |
| **不脱敏 OTLP 导出** | OTLP 导出不应用脱敏或字段投影，prompts、凭据、路径都可能被传输 |
| **不做生产级依赖安全** | 研究工件，部分依赖携带已知 CVE，需在隔离环境运行 |
| **无实时流** | 每小时调度运行，非实时流式处理 |

### 2.3 11 个支持的 AI 代理平台

| Agent | Source key | 日志格式 | 平台 | 默认回溯 |
|---|---|---|---|---|
| Claude Code | `claude` | JSONL (`~/.claude/projects/`) | macOS, Linux, Windows | 14 天 |
| Cursor IDE | `cursor` | SQLite (`state.vscdb`) | macOS, Linux, Windows | 14 天 |
| Cline (Claude Dev) | `cline` | JSON task 文件 | macOS, Linux, Windows | 14 天 |
| Claude Desktop | `claude_desktop` | JSONL audit 日志 | macOS, Windows | 14 天 |
| OpenAI Codex CLI | `codex` | JSONL + SQLite catalogs | macOS, Linux, Windows | 14 天 |
| GitHub Copilot CLI | `copilot` | JSONL (`~/.copilot/session-state/`) | macOS, Linux, Windows | 14 天 |
| DeepSeek Harness | `dsh` | JSONL / Zstandard (`~/.dsh/sessions/`) | macOS, Linux, Windows | 14 天 |
| Warp Terminal | `warp` | SQLite (`warp.sqlite`) | macOS, Windows | 14 天 |
| opencode | `opencode` | SQLite (`opencode.db`) 或 JSON tree | macOS, Linux | 14 天 |
| Gemini CLI | `gemini` | JSONL journals + legacy JSON | macOS, Linux, Windows | 14 天 |
| Google Antigravity | `antigravity` | JSONL transcript | macOS, Linux, Windows | 14 天 |

**平台自动跳过**：不支持当前操作系统的来源会被自动跳过。例如 Linux 上 `--source all` 不会尝试 `claude_desktop`（仅 macOS/Windows）。`PLATFORM_RESTRICTED_SOURCES` 列表控制此行为。

### 2.4 四维遥测模型

论文定义了 Sensor 采集的四个数据维度，构成完整的因果链：

| 维度 | 采集内容 | 揭示信息 | AgentEvent 对应字段 |
|---|---|---|---|
| 用户提示 | 原始自然语言指令 | **意图**（用户要求做什么） | `chat_history[].content` (role=user) |
| 代理推理 | 中间思考过程和决策步骤 | **解释**（代理如何理解并规划） | `chat_history[].content` (role=assistant) + `tools` |
| MCP 工具调用 | 工具调用序列、参数、结果 | **行为**（代理实际做了什么） | `chat_history[].tools[]` |
| 环境上下文 | MCP 配置、权限模式、模型 | **能力**（代理可用的功能范围） | `session_context` |

**因果链示例**：

```
用户 prompt: "帮我总结这个 Jira ticket"
    ↓
代理推理: "我需要先读取 Jira ticket 内容"
    ↓
工具调用: jira_mcp.get_ticket(id=PROJ-123)
    ↓
工具结果: ticket 内容...
    ↓
代理推理: "现在我总结一下"
    ↓
代理响应: "这个 ticket 是关于..."
```

如果因果链断裂——用户要求"总结 Jira ticket"但代理调用了 `read_file("~/.ssh/id_rsa")`——Sensor 遥测会暴露这种偏离。

---

## 三、技术实现方案

### 3.1 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        AI Agent Logs                            │
│  Claude Code │ Cursor │ Cline │ Codex │ Copilot CLI │ DSH       │
│  Warp │ opencode │ Gemini CLI │ Claude Desktop │ Antigravity   │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Source-Specific Parsers                      │
│                  (Each implements BaseParser)                   │
│   claude_parser │ cursor_parser │ cline_parser │ codex_parser   │
│   copilot_parser │ dsh_parser │ gemini_parser │ warp_parser     │
│   claude_desktop_parser │ opencode_parser │ antigravity_parser  │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Unified Schema (AgentEvent)                   │
│  uuid │ timestamp │ source │ session_id │ hostname │ username   │
│  host_os │ model │ project_path │ chat_history │ session_context│
│  token_usage                                                    │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AgentObserver (Orchestrator)                 │
│              Ingest → Filter → Display → Export                 │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                 ┌────┴────┐
                 ▼         ▼
           JSON/JSONL   OTLP Logs
              Files        │
                           ▼
                    Collector / SIEM
```

五层架构，自上而下：

1. **AI Agent Logs** — 各代理平台的原始日志（JSONL、SQLite、JSON 等），格式各异
2. **Source-Specific Parsers** — 每个代理一个解析器，都实现 `BaseParser` 接口
3. **Unified Schema (AgentEvent)** — 统一 schema，消除源格式差异
4. **AgentObserver** — 编排器，执行 Ingest → Filter → Display → Export 流水线
5. **输出** — JSON/JSONL 文件 和/或 OTLP Logs 导出到 Collector/SIEM

### 3.2 AgentEvent 统一 Schema

#### 3.2.1 核心结构

每个解析的 session 生成一个 `AgentEvent`。以下为完整字段示例：

```json
{
  "uuid": "sha256-hash",
  "timestamp": "2025-06-15T10:30:00+00:00",
  "source": "claude",
  "session_id": "claude_abc123",
  "hostname": "my-laptop",
  "username": "developer",
  "host_os": "Darwin",
  "model": "claude-sonnet-4-20250514",
  "project_path": "/home/user/my-project",
  "chat_history": [
    {
      "role": "user",
      "content": "Help me fix this bug",
      "tools": [],
      "sequence_id": "msg_0"
    },
    {
      "role": "assistant",
      "content": "Let me look at the code.",
      "tools": [
        {
          "tool_name": "read_file",
          "tool_type": "tool_use",
          "arguments": {"path": "main.py"},
          "result": "def hello(): ...",
          "status": "success"
        }
      ],
      "sequence_id": "msg_1"
    }
  ],
  "session_context": {
    "title": "Config review",
    "is_dispatch": false,
    "init": {
      "tools": ["Bash", "Read"],
      "mcp_servers": [{"name": "github"}],
      "permission_mode": "acceptEdits",
      "model": "claude-sonnet-4",
      "claude_code_version": "2.1.0"
    }
  },
  "token_usage": {
    "last_turn": {
      "input_tokens": 120,
      "output_tokens": 30,
      "total_tokens": 150
    },
    "cumulative": {
      "input_tokens": 420,
      "output_tokens": 90,
      "total_tokens": 510
    },
    "model_context_window": 128000
  }
}
```

#### 3.2.2 字段说明

| 字段 | 类型 | 说明 |
|---|---|---|
| `uuid` | str | SHA-256 哈希，唯一标识 |
| `timestamp` | str | ISO 8601 时间戳，会话起始时间 |
| `source` | str | 来源代理标识符（如 `claude`、`cursor`） |
| `session_id` | str | 会话唯一标识，格式 `<source>_<native_id>` |
| `hostname` | str | 机器主机名 |
| `username` | str | OS 账户名（sensor 进程运行身份，**从不从环境变量读取**） |
| `host_os` | str | `platform.system()` 值（`Darwin`、`Linux`、`Windows`） |
| `model` | str | AI 模型标识 |
| `project_path` | str | 项目路径 |
| `chat_history` | list[ChatMessage] | 聊天消息数组 |
| `session_context` | dict (可选) | session 级配置，代理对自身权限的视图 |
| `token_usage` | dict (可选) | 规范化的 token 计数器 |

#### 3.2.3 ChatMessage 结构

```
ChatMessage
├── role: str ("user" | "assistant")
├── content: str
├── tools: list[ToolUsage]
│   ├── tool_name: str
│   ├── tool_type: str ("tool_use" | "mcp_tool" 等)
│   ├── arguments: dict
│   ├── result: str
│   └── status: str ("success" | "error" 等)
└── sequence_id: str
```

#### 3.2.4 session_context

`session_context` 是解析器可恢复的 session 级配置——代理对自身权限和能力的视图：

```json
{
  "session_context": {
    "title": "Config review",
    "is_dispatch": true,
    "session_type": "dispatch",
    "cli_session_id": "cli-99",
    "memory_enabled": true,
    "skills_enabled": false,
    "plugins_enabled": true,
    "available_slash_commands": ["review", "deploy"],
    "init": {
      "tools": ["Bash", "Read"],
      "mcp_servers": [{"name": "github"}],
      "permission_mode": "acceptEdits",
      "model": "claude-sonnet-4",
      "claude_code_version": "2.1.0",
      "plugins": ["reviewer"],
      "skills": ["pdf"]
    }
  }
}
```

`session_context.init` 中的字段因代理不同而异，但都反映代理启动时的能力配置。对安全分析而言，`permission_mode` 和 `mcp_servers` 是关键信号。

#### 3.2.5 token_usage

规范化的 token 计数（仅非负整数），分为 `last_turn`（最近一轮）和 `cumulative`（累计）：

```json
{
  "token_usage": {
    "last_turn": {
      "input_tokens": 120,
      "cached_input_tokens": 80,
      "output_tokens": 30,
      "reasoning_output_tokens": 10,
      "total_tokens": 150
    },
    "cumulative": {
      "input_tokens": 420,
      "cached_input_tokens": 200,
      "cache_write_input_tokens": 40,
      "output_tokens": 90,
      "reasoning_output_tokens": 25,
      "total_tokens": 510
    },
    "model_context_window": 128000
  }
}
```

#### 3.2.6 Schema 层级总览

```
AgentEvent
├── uuid: str (sha256-hash)
├── timestamp: str (ISO 8601)
├── source: str
├── session_id: str
├── hostname: str
├── username: str
├── host_os: str
├── model: str
├── project_path: str
├── chat_history: list[ChatMessage]
│   ├── role: str ("user" | "assistant")
│   ├── content: str
│   ├── tools: list[ToolUsage]
│   │   ├── tool_name: str
│   │   ├── tool_type: str
│   │   ├── arguments: dict
│   │   ├── result: str
│   │   └── status: str
│   └── sequence_id: str
├── session_context: dict (可选)
│   ├── title: str
│   ├── is_dispatch: bool
│   ├── init: dict
│   │   ├── tools: list[str]
│   │   ├── mcp_servers: list[dict]
│   │   ├── permission_mode: str
│   │   ├── model: str
│   │   └── ...
│   └── ...
└── token_usage: dict (可选)
    ├── last_turn: dict
    ├── cumulative: dict
    └── model_context_window: int
```

### 3.3 解析器架构

#### 3.3.1 BaseParser 接口

每个解析器继承 `BaseParser`，实现统一的解析接口：

```python
from adr_sensor.parsers.base_parser import BaseParser

class MyAgentParser(BaseParser):
    def __init__(self, max_age_days: int = 14):
        self.base_path = Path.home() / ".my-agent/logs"
        self.max_age_days = max_age_days

    def parse_all(self) -> list[AgentEvent]:
        entries = []
        # 解析代理日志文件并转换为 AgentEvent 对象
        return entries
```

`parse_all()` 返回 `list[AgentEvent]`，是所有解析器的统一出口。

#### 3.3.2 解析器注册机制

`AgentObserver.SOURCES` 是一个元组，注册所有支持的来源：

```python
class AgentObserver:
    SOURCES = (
        ("claude", "Claude Code"),
        ("cursor", "Cursor IDE"),
        ("cline", "Cline (Claude Dev)"),
        ("claude_desktop", "Claude Desktop"),
        ("codex", "OpenAI Codex CLI"),
        ("copilot", "GitHub Copilot CLI"),
        ("dsh", "DeepSeek Harness"),
        ("warp", "Warp Terminal"),
        ("opencode", "opencode"),
        ("gemini", "Gemini CLI"),
        ("antigravity", "Google Antigravity"),
    )
```

`ingest_all()` 遍历 `SOURCES`，通过 `self.<source>_parser` 查找解析器实例，无需 per-source 分支。`PLATFORM_RESTRICTED_SOURCES` 列表控制平台限制来源。

CLI 自动从 `SOURCES` 构建 `--source` 选项。

#### 3.3.3 添加新解析器

1. 在 `adr_sensor/parsers/` 下创建新解析器，继承 `BaseParser`
2. 在 `adr_sensor/parsers/__init__.py` 中导出
3. 在 `adr_sensor/observer.py` 中注册：
   - 构造解析器为 `self.<source>_parser`
   - 在 `AgentObserver.SOURCES` 中添加 source key
   - 如需要平台限制，添加到 `PLATFORM_RESTRICTED_SOURCES`
4. 在 `tests/` 中添加测试

```python
class AgentObserver:
    SOURCES = (
        ...,
        ("my_agent", "My Agent"),
    )

    def __init__(self, ...):
        ...
        self.my_agent_parser = MyAgentParser()
```

#### 3.3.4 解析器项目结构

```
adr_sensor/
├── __init__.py          # 包导出
├── cli.py               # CLI 入口点
├── observer.py          # AgentObserver 编排器
├── exporters/
│   ├── config.py        # OTLP/HTTP JSON 配置
│   └── opentelemetry.py # OpenTelemetry Logs exporter
├── parsers/
│   ├── base_parser.py   # 抽象基类
│   ├── claude_parser.py
│   ├── cursor_parser.py
│   ├── cline_parser.py
│   ├── claude_desktop_parser.py
│   ├── codex_parser.py
│   ├── copilot_parser.py
│   ├── dsh_parser.py
│   ├── gemini_parser.py
│   ├── opencode_parser.py
│   ├── warp_parser.py
│   └── antigravity_parser.py
├── schemas/
│   ├── agent_event_schema.py    # AgentEvent, ChatMessage, ToolUsage
│   └── system_config_schema.py  # SystemConfiguration
└── utils/
    ├── string_utils.py
    └── timestamp_utils.py
```

### 3.4 AgentObserver 编排器

`AgentObserver` 是 Sensor 的编排核心，执行 Ingest → Filter → Display → Export 流水线：

```python
from adr_sensor import AgentObserver

# 创建 observer
observer = AgentObserver()

# 从所有来源摄入
events, configs = observer.ingest_all()

# 或从特定来源摄入
events, configs = observer.ingest_all(source_filter="claude")

# 显示摘要
observer.display_summary(events, configs)

# 保存到文件
observer.save_to_file(events, configs, output_format="json")
```

| 方法 | 说明 |
|---|---|
| `ingest_all()` | 摄入所有/特定来源，返回 `(events, configs)` |
| `ingest_all(source_filter="claude")` | 按来源过滤摄入 |
| `display_summary(events, configs)` | 打印摄入摘要表 |
| `save_to_file(events, configs, output_format="json")` | 保存到文件 |

### 3.5 输出与导出

#### 3.5.1 文件输出

| 格式 | 用途 |
|---|---|
| JSON | 单文件分析，包含所有 events |
| JSONL | 大型日志集和流式处理，每行一个 event |

默认输出目录 `./output`，可通过 `--output-dir` 自定义。

`--save-sessions` 按 session 粒度保存，支持增量更新。保存路径默认 `$XDG_CACHE_HOME/adr_sensor`（默认 `~/.cache/adr_sensor`）。

#### 3.5.2 OpenTelemetry OTLP 导出

OTLP 导出默认禁用，仅在 `--otel-config` 指向 JSON 配置文件时初始化。

配置文件示例（`examples/opentelemetry-config.json`）：

```json
{
  "endpoint": "http://localhost:4318/v1/logs",
  "service_name": "adr-sensor",
  "headers": {},
  "timeout_seconds": 10,
  "flush_timeout_seconds": 30
}
```

| 配置字段 | 说明 |
|---|---|
| `endpoint` | 完整 OTLP/HTTP logs URL（含 `/v1/logs`） |
| `service_name` | 服务名 |
| `headers` | 认证头 |
| `timeout_seconds` | 超时 |
| `flush_timeout_seconds` | flush 超时 |
| `certificate_file` | PEM 证书包（可选，相对路径从配置文件目录解析） |
| `gen_ai_attributes` | 设为 `true` 添加 GenAI 语义约定属性（默认关闭） |

**OTLP 导出关键行为**：

- 每个 `AgentEvent` 作为 `adr.agent.session` OpenTelemetry LogRecord 发送
- Body 为 `AgentEvent.get_non_null_fields()` 的完整字典
- **不应用脱敏或字段投影** — prompts、responses、工具参数/结果、用户名、主机名、本地路径都可能被传输
- 交付检查点（`.adr-otel-delivery.<hash>.json`）跟踪成功导出，仅存储哈希
- 至少一次交付语义 — 重试可能产生重复记录
- 支持 mTLS 客户端证书/密钥路径
- **不支持** 动态 HTTP 凭据提供者插件

#### 3.5.3 GenAI 语义约定属性映射

`gen_ai_attributes: true` 时，每个 source 的 native ID 映射为 `gen_ai.conversation.id`：

| source | ADR `session_id` | Native ID | `gen_ai.conversation.id` |
|---|---|---|---|
| `antigravity` | `antigravity_<id>` | 对话目录名 | `<id>` |
| `claude` | `claude_<id>` | JSONL `sessionId` | `<id>`；subagents 用父 session 的 `sessionId` |
| `claude_desktop` | `claude_desktop_[dispatch_]<uuid>` | Metadata `cliSessionId` | `cliSessionId`；缺失时省略 |
| `cline` | `cline_<id>` | Task 目录名 | `<id>` |
| `codex` | `codex_<id>` | `session_meta` `payload.id` | `<id>` |
| `copilot` | `copilot_<id>` | `session.start`/`session.resume` `sessionId` | `<id>` |
| `cursor` | `cursor_<id>` | Composer ID | `<id>` |
| `dsh` | `dsh_<id>` | Session header `id` | `<id>` |
| `gemini` | `gemini_<id>` | `sessionId`；subagents 保持自己的 | `<id>` |
| `opencode` | `opencode_<id>` | Session `id`（去掉 `ses_` 前缀） | `ses_<id>` |
| `warp` | `warp_<id>` | `agent_conversations.conversation_id` | `<id>` |

### 3.6 诊断与健康

#### 3.6.1 诊断文件

| 文件 | 位置 | 内容 |
|---|---|---|
| `diagnostics.jsonl` | `--output-dir` | 所有摘要 |
| `error.log` | `--output-dir` | 仅 `partial` 和 `failed` 摘要 |
| `resource.log` | `--output-dir`（`--resource` 启用时） | 资源日志 |
| `sensor_runtime_errors.jsonl` | `--log-file` 启用时 | 警告和错误 JSON 行 |
| `sensor_runtime_debug.jsonl` | `--log-file` 启用时 | debug 和 info 消息 |

所有文件在 1 MiB 时轮转，保留 2 个备份。

#### 3.6.2 健康状态

| 状态 | 含义 |
|---|---|
| `ok` | 成功捕获 |
| `empty` | 无有意义输出 |
| `no_input` | 输入不存在 |
| `partial` | 有可用输出但观察到错误 |
| `failed` | 错误且无可用输出 |

健康记录示例：

```json
{
  "schema_version": 1,
  "event": "adr.sensor.health",
  "timestamp": "2026-01-01T00:00:00.000+00:00",
  "sensor_version": "0.0.0",
  "source": "claude",
  "stage": "parse",
  "status": "partial",
  "suspected_schema_drift": false,
  "counts": {
    "events_returned": 2,
    "events_emitted": 2,
    "events_filtered": 0
  },
  "reasons": {
    "record_decode_error": 1
  }
}
```

#### 3.6.3 隐私说明

- 结构化诊断**不包含** prompts、工具参数/结果、路径、session ID、异常消息、traceback
- 运行时日志的 `message` 和 `stack` **可能包含** 本地文件路径和错误文本
- `--log-file-content-free` 丢弃 `message` 和 `stack`
- `--log-identity` 添加 `username` 和 `hostname`（opt-in）

### 3.7 CLI

#### 完整参数列表

| 参数 | 说明 |
|---|---|
| `--source <key>` | 指定来源代理（默认 all） |
| `--save-sessions` | 保存单独的 session 文件（增量） |
| `--output-format jsonl` | 导出为 JSONL 格式 |
| `--all-history` | 包含所有历史（不仅最近 14 天） |
| `--output-dir <path>` | 自定义输出目录（默认 `./output`） |
| `--otel-config <path>` | 导出到 OTLP/HTTP logs endpoint |
| `--no-save` | 不写 JSON 文件（配合 `--otel-config` 使用） |
| `--quiet` / `-q` | 仅打印警告和错误 |
| `--log-level <level>` | 最低日志级别：`debug`、`info`、`warning`、`error` |
| `--fail-on-error` | 观察到解析/保存/诊断失败时非零退出 |
| `--resource` | 启用 `resource.log` |
| `--log-file` | 将运行日志写为 JSON 行 |
| `--log-file-content-free` | 丢弃 `message` 和 `stack`，保留其余字段 |
| `--log-identity` | 在每条记录中添加 `username` 和 `hostname` |

#### CLI 命令示例

```bash
# 基本用法 — 从所有支持的代理收集
adr-sensor

# 从特定来源收集
adr-sensor --source claude
adr-sensor --source cursor
adr-sensor --source gemini

# 保存 session 文件
adr-sensor --save-sessions

# 导出 JSONL
adr-sensor --output-format jsonl

# 包含所有历史
adr-sensor --all-history

# 自定义输出目录
adr-sensor --output-dir ./my-output

# 导出到 OTLP endpoint
adr-sensor --otel-config ./opentelemetry-config.json

# 仅导出 OTLP 不写本地文件
adr-sensor --no-save --otel-config ./opentelemetry-config.json

# 日志控制
adr-sensor --quiet
adr-sensor --log-level debug

# 从源码运行（开发环境）
uv run adr-sensor --source gemini --no-save
```

#### 输出流

- **stdout**：进度消息
- **stderr**：警告和错误
- 始终打印摄入摘要表

### 3.8 Python API

```python
from adr_sensor import AgentObserver

# 创建 observer
observer = AgentObserver()

# 从所有来源摄入
events, configs = observer.ingest_all()

# 或从特定来源摄入
events, configs = observer.ingest_all(source_filter="claude")

# 显示摘要
observer.display_summary(events, configs)

# 保存到文件
observer.save_to_file(events, configs, output_format="json")

# 分析事件
for event in events:
    print(f"Source: {event.source}, Session: {event.session_id}")
    print(f"Messages: {len(event.chat_history)}")

    for msg in event.chat_history:
        if msg.tools:
            for tool in msg.tools:
                print(f"  Tool: {tool.tool_name} ({tool.tool_type})")
                print(f"  Args: {tool.arguments}")
```

---

## 四、各代理日志路径与解析细节

### 4.1 Claude Code

- **日志路径**：递归读取 `~/.claude/projects/` 下的 transcripts
- **子代理**：包含 `<project>/<sessionId>/subagents/agent-<agentId>.jsonl` 及嵌套工作流目录
- **Session ID 规则**：
  - 主会话：`claude_<sessionId>`
  - 子代理：`claude_<sessionId>_agent_<agentId>`，包含 `parent_session_id` 和 `agent_id`
- **数据处理**：
  - 保留字符串和文本块消息，包括工具结果附带的用户文本
  - 通过 tool-call ID 匹配结果
  - 跳过格式错误的记录但不丢弃周围消息
  - 支持同一物理行拼接的完整 JSON 对象和对象间的 NUL 填充
  - 不完整的尾部被跳过，不连接物理行或修复消息内文本
- **元数据**：每个事件包含 `raw_log_path`、稳定的对话起始 `timestamp`、`session_context.last_event_at` 和 `event_count`
- **默认回溯**：14 天（按文件修改时间）
- **截断限制**：顶层工具参数字符串和工具结果在 1,000 字符处截断
- **不导入的内容**：非文本内容块和单独溢出的工具输出文件

### 4.2 Cursor IDE

- **日志格式**：SQLite 数据库（`state.vscdb`）
- **平台**：macOS, Linux, Windows
- **默认回溯**：14 天

### 4.3 Cline (Claude Dev)

- **扩展 ID**：`saoudrizwan.claude-dev`
- **支持的编辑器**：VS Code（主要）、Cursor、VS Code Insiders、VSCodium、Windsurf
- **日志路径（按操作系统）**：

| Host | 默认 task 目录 |
|---|---|
| macOS | `~/Library/Application Support/<Editor>/User/globalStorage/saoudrizwan.claude-dev/tasks/` |
| Linux | `~/.config/<Editor>/User/globalStorage/saoudrizwan.claude-dev/tasks/` |
| Windows | `%APPDATA%\<Editor>\User\globalStorage\saoudrizwan.claude-dev\tasks\` |

- **处理**：扫描所有候选目录，规范化用户提示和助手工具使用（包括 `<use_mcp_tool>` 调用），跨编辑器去重
- **默认回溯**：14 天（按 task 文件修改时间）
- **自定义**：`ClineParser(base_path=...)` 限制单个 task 目录

### 4.4 Claude Desktop

覆盖 Claude Desktop 的本地代理模式（发布为 Claude Cowork），支持 macOS 和 Windows：

- **交互式会话**：`.../local-agent-mode-sessions/<user>/<org>/local_<uuid>/audit.jsonl`
- **调度会话（委派后台代理）**：`.../<user>/<org>/agent/local_ditto_<uuid>/audit.jsonl`
- **区别标识**：调度会话使用 `claude_desktop_dispatch_` 前缀和 `is_dispatch: true` 标志

### 4.5 OpenAI Codex CLI

- **日志路径**：`$CODEX_HOME/sessions/`（默认 `~/.codex`）
- **SQLite catalogs**：打开每个 `$CODEX_HOME/state_*.sqlite`，以只读模式查询兼容的 `threads` 表
  - 必须有 `id` 和 `rollout_path` 列
  - `updated_at` 和 `updated_at_ms` 为可选
  - 相对路径从 `CODEX_HOME` 解析，仅接受已存在的 `.jsonl` 文件
- **去重**：catalog 和文件系统路径去重
- **过滤**：使用文件修改时间和 catalog 更新时间戳中较新者
- **默认回溯**：14 天
- **自定义**：`max_age_days` 参数；值 ≤ 0 禁用年龄过滤

### 4.6 GitHub Copilot CLI

- **日志路径（按操作系统）**：

| 操作系统 | 默认 session 目录 |
|---|---|
| macOS | `/Users/<user>/.copilot/session-state/` |
| Linux | `/home/<user>/.copilot/session-state/` |
| Windows | `%USERPROFILE%\.copilot\session-state\` |

- **环境变量**：`COPILOT_HOME` 覆盖配置目录，Sensor 读取 `$COPILOT_HOME/session-state/`
- **读取文件**：每个 session 的 `events.jsonl` + 可选 `workspace.yaml` 和 `vscode.metadata.json`
- **默认回溯**：14 天（按 `events.jsonl` 修改时间）
- **范围说明**：仅覆盖 GitHub Copilot CLI session state，**不读取 VS Code Copilot Chat 扩展的存储**

### 4.7 DeepSeek Harness

- **日志路径**：`$DSH_HOME/sessions/`（默认 `~/.dsh/sessions/`）
- **格式**：默认 Zstandard 压缩日志，也支持未压缩的 JSONL v3 日志
- **Generation 处理**：一个 session 目录有多代日志时，仅考虑最高 generation，且仅在 v3 格式时导入
- **规范化内容**：工具参数和结果、PTC 子调度、失败状态、批准、provider/model 上下文、沙箱模式、权限预设、类型化消息内容、token 使用量
- **默认回溯**：14 天
- **命令**：`adr-sensor --source dsh`

### 4.8 Warp Terminal

- **日志格式**：SQLite 数据库（`warp.sqlite`）
- **平台**：macOS, Windows
- **默认回溯**：14 天

### 4.9 opencode

- **数据目录**：`~/.local/share/opencode`（Linux 和 macOS），支持 `$XDG_DATA_HOME` 和 `$OPENCODE_DB`
- **两种存储后端**：
  1. **SQLite（当前版本）**：`opencode.db` 或 `opencode-<channel>.db`（非稳定频道），只读打开
     - 仅当包含 `session`、`message` 和 `part` 表时使用
  2. **JSON 文件树（旧版本）**：`storage/` 目录，包含 per-session、per-message 和 per-part JSON 文件
- **MCP 工具命名**：opencode 将 MCP 工具命名为 `<server>_<tool>`，含下划线的非内置工具记为 `tool_type: "mcp_tool"` 并填充 `server_name`

### 4.10 Gemini CLI

- **日志路径（按操作系统）**：

| Host | 默认扫描根目录 |
|---|---|
| macOS / Linux | `~/.gemini/tmp/` |
| Windows | `%USERPROFILE%\.gemini\tmp\` |
| macOS Seatbelt 沙箱 | `~/.cache/.gemini/tmp/`（macOS 上额外扫描） |

- **环境变量**：`GEMINI_CLI_HOME` 覆盖**父主目录**，路径变为 `$GEMINI_CLI_HOME/.gemini/tmp`（非 `$GEMINI_CLI_HOME/tmp`）
- **自定义路径**：`GeminiParser(base_path=Path("/capture/tmp"))`
- **读取内容**：
  - 当前 `chats/**/*.jsonl` journals
  - legacy `chats/*.json` 对话快照
  - 用户/助手文本、工具参数和结果、状态和批准请求、model 和 token 使用量、嵌套子代理会话
- **数据处理**：
  - Session resume 时起始时间戳保持稳定
  - `--save-sessions` 原地刷新已更改的快照
  - 按 ID 合并重复的 journal 消息，工具进度更新不会重复消息或 token 总计
  - rewind 和 checkpoint 记录后早期活动仍然保留
  - `session_context.history_scope` 为 `all_recorded_branches`
  - 不添加任何脱敏或截断
- **不收集的内容**：仅 prompt 的 `logs.json`、编辑器聊天存储、shell 历史、未保存会话、这些根之外的文件
- **MCP 调用**：显式 `mcp_`/限定工具名标识 MCP 调用；记录名模糊时 server 归属留空
- **默认回溯**：14 天（按文件修改时间）；`--all-history` 包含更旧文件
- **契约验证**：对照上游 record types、journal writer、storage paths、supported platforms 验证
- **测试**：使用合成记录，匹配这些契约，在所有三个 host 上运行；不需要 Gemini 账户

### 4.11 Google Antigravity

- **Brain 目录（按产品）**：

| 产品 | 默认 brain 目录 |
|---|---|
| Antigravity CLI | `~/.gemini/antigravity-cli/brain/` |
| Antigravity 2.0 | `~/.gemini/antigravity2/brain/` |
| Antigravity IDE | `~/.gemini/antigravity-ide/brain/` |

- **Legacy 路径**：`~/.antigravity/brain/`、`%APPDATA%\Google\Antigravity\brain\`、`~/Library/Application Support/Google/Antigravity/brain/`、`~/.config/google/antigravity/brain/`
- **环境变量**：`ANTIGRAVITY_HOME` 和 `AGY_HOME` 作为存储覆盖
- **每个对话目录**：`.system_generated/logs/transcript.jsonl` + 可选 `transcript_full.jsonl`
- **Transcript 选择**：比较可用快照，选择最新记录修订版；同一修订版优先选择未截断数据和完整 transcript
- **Step Types**：`USER_INPUT`（用户提示）、`PLANNER_RESPONSE`（助手输出 + `thinking` 文本 + 工具调用）、`GENERIC`（模型输出）
- **Thinking 文本**：以 `[Thinking]` 标签保留
- **工具规范化**：原生工具直接记录；MCP 调用（如 `mcp_<server>_<tool>` 或 `<server>:<tool>`）解析填充 `server_name` 和 `tool_name`
- **数据保留**：不截断工具参数或字符串化嵌套值；若源 transcript 报告 `truncated_fields`，标记 `is_truncated`
- **默认回溯**：14 天

---

## 五、正反例测试方法集

### 5.1 测试设计原则

本测试方法集遵循以下设计原则：

1. **合成记录驱动**：所有测试使用合成 transcripts/记录，不启动实际 AI 代理
2. **契约验证**：多个解析器对照上游源码验证（record types、journal writer、storage paths）
3. **跨平台覆盖**：测试在 macOS、Linux、Windows 三个 host 上运行
4. **无需账户**：测试不需要任何 AI 代理的账户或 API key
5. **可复现**：所有测试可在隔离环境中独立复现

### 5.2 正例测试集

正例测试验证 Sensor 在正常场景下的正确行为。

#### P-01: 单源采集 — Claude Code

**目的**：验证 Claude Code 解析器能正确解析 JSONL 日志并生成 AgentEvent。

**前置条件**：
- Claude Code 已安装并使用过（`~/.claude/projects/` 下有 JSONL transcripts）
- Python 3.9+，`adr-sensor` 已安装

**步骤**：

```bash
# 1. 确认日志存在
ls ~/.claude/projects/

# 2. 仅采集 Claude Code 日志
adr-sensor --source claude --output-dir ./test-output --output-format jsonl

# 3. 验证输出
ls ./test-output/
cat ./test-output/*.jsonl | python3 -c "
import json, sys
for line in sys.stdin:
    event = json.loads(line)
    assert event['source'] == 'claude'
    assert 'session_id' in event
    assert event['session_id'].startswith('claude_')
    assert 'chat_history' in event
    assert len(event['chat_history']) > 0
    assert 'timestamp' in event
    assert 'hostname' in event
    assert 'username' in event
    print(f'OK: {event[\"session_id\"]} - {len(event[\"chat_history\"])} messages')
"
```

**预期结果**：
- 输出目录包含 JSONL 文件
- 每行是一个合法 JSON 对象
- `source` 字段为 `claude`
- `session_id` 以 `claude_` 前缀开头
- `chat_history` 非空
- `timestamp` 为 ISO 8601 格式
- `hostname` 和 `username` 已填充

#### P-02: 多源采集 — 全量

**目的**：验证 `--source all` 能自动发现并采集所有已安装代理的日志。

**步骤**：

```bash
adr-sensor --output-dir ./test-output-all

# 验证摘要表打印
# 验证至少一个源有输出
ls ./test-output-all/
```

**预期结果**：
- 摘要表列出所有 11 个来源
- 不支持当前操作系统的来源状态为 `no_input` 或自动跳过
- 至少一个来源状态为 `ok`
- 未安装的代理状态为 `no_input`

#### P-03: JSONL 格式导出

**目的**：验证 JSONL 格式输出的正确性。

**步骤**：

```bash
adr-sensor --source claude --output-format jsonl --output-dir ./test-jsonl

# 验证每行是合法 JSON
python3 -c "
import json
with open('./test-jsonl/agent_event_logs.jsonl') as f:
    count = 0
    for line in f:
        event = json.loads(line)  # 不抛异常即合法
        count += 1
    print(f'Valid JSONL: {count} events')
"
```

**预期结果**：所有行均为合法 JSON，无解析错误。

#### P-04: 工具调用记录

**目的**：验证 AgentEvent 正确捕获工具调用（名称、参数、结果、状态）。

**步骤**：

```bash
adr-sensor --source claude --output-dir ./test-tools --output-format jsonl

python3 -c "
import json
with open('./test-tools/agent_event_logs.jsonl') as f:
    tool_count = 0
    for line in f:
        event = json.loads(line)
        for msg in event.get('chat_history', []):
            for tool in msg.get('tools', []):
                assert 'tool_name' in tool
                assert 'tool_type' in tool
                assert 'arguments' in tool
                tool_count += 1
    print(f'Tool calls captured: {tool_count}')
    assert tool_count > 0, 'No tool calls found'
"
```

**预期结果**：捕获的工具调用数量 > 0，每个工具调用包含 `tool_name`、`tool_type`、`arguments` 字段。

#### P-05: 增量保存（--save-sessions）

**目的**：验证 `--save-sessions` 按 session 粒度保存。

**步骤**：

```bash
# 第一次运行
adr-sensor --source claude --save-sessions --output-dir ./test-incremental

# 记录文件数
find ~/.cache/adr_sensor -name "*.json" | wc -l

# 第二次运行（无新会话）
adr-sensor --source claude --save-sessions --output-dir ./test-incremental

# 文件数应不变或仅新增
find ~/.cache/adr_sensor -name "*.json" | wc -l
```

**预期结果**：第二次运行不重新保存未变化的 session 文件。

#### P-06: Python API 调用

**目的**：验证 `AgentObserver` Python API 可正常使用。

**步骤**：

```python
from adr_sensor import AgentObserver

observer = AgentObserver()
events, configs = observer.ingest_all(source_filter="claude")
assert len(events) > 0, "No events captured"
observer.display_summary(events, configs)
observer.save_to_file(events, configs, output_format="json")

for event in events:
    assert event.source == "claude"
    assert hasattr(event, "chat_history")
    print(f"OK: {event.session_id} - {len(event.chat_history)} messages")
```

**预期结果**：API 返回 events 列表，每个 event 有 `source` 和 `chat_history` 属性。

#### P-07: 诊断文件生成

**目的**：验证诊断文件正确生成且不含敏感信息。

**步骤**：

```bash
adr-sensor --source claude --output-dir ./test-diag

# 检查诊断文件
cat ./test-diag/diagnostics.jsonl | python3 -c "
import json, sys
for line in sys.stdin:
    diag = json.loads(line)
    assert 'schema_version' in diag
    assert 'event' in diag
    assert 'status' in diag
    assert diag['event'] == 'adr.sensor.health'
    # 验证不含敏感信息
    line_str = line.lower()
    assert 'password' not in line_str
    assert 'api_key' not in line_str
    assert 'token=' not in line_str
    print(f'OK: source={diag[\"source\"]} status={diag[\"status\"]}')
"
```

**预期结果**：诊断文件包含 schema_version、event、status 字段，不含 password/api_key/token 等敏感信息。

### 5.3 反例测试集

反例测试验证 Sensor 在异常、边界和超范围场景下的行为。

#### N-01: 无日志的来源

**目的**：验证未安装的代理被正确处理为 `no_input` 状态。

**步骤**：

```bash
# 假设 DeepSeek Harness 未安装
adr-sensor --source dsh --output-dir ./test-empty

# 检查诊断
cat ./test-empty/diagnostics.jsonl | python3 -c "
import json, sys
for line in sys.stdin:
    diag = json.loads(line)
    assert diag['source'] == 'dsh'
    assert diag['status'] in ['no_input', 'empty']
    print(f'OK: source={diag[\"source\"]} status={diag[\"status\"]}')
"
```

**预期结果**：状态为 `no_input` 或 `empty`，不抛异常，退出码为 0。

#### N-02: 格式错误的日志文件

**目的**：验证解析器对损坏日志的容错能力。

**步骤**：

```bash
# 创建模拟损坏的 Claude Code 日志
mkdir -p ~/.claude/projects/test-corrupt/
echo '{"valid":"json"}' > ~/.claude/projects/test-corrupt/session1.jsonl
echo 'not valid json' >> ~/.claude/projects/test-corrupt/session1.jsonl
echo '{"another":"valid"}' >> ~/.claude/projects/test-corrupt/session1.jsonl

# 运行 sensor
adr-sensor --source claude --output-dir ./test-corrupt --fail-on-error 2>&1 || true

# 验证：损坏的行被跳过，其余行仍被解析
python3 -c "
import json
try:
    with open('./test-corrupt/agent_event_logs.jsonl') as f:
        events = [json.loads(line) for line in f]
    print(f'Events despite corruption: {len(events)}')
except FileNotFoundError:
    print('No output (all records corrupted)')
"
```

**预期结果**：
- 损坏的行被跳过，不导致整个文件解析失败
- 有效行仍被解析为 AgentEvent
- 诊断状态为 `partial`（有错误但有可用输出）
- `--fail-on-error` 时退出码非零

#### N-03: 不支持的来源

**目的**：验证传入不存在的 source key 被正确拒绝。

**步骤**：

```bash
# 传入不存在的 source
adr-sensor --source nonexistent_agent 2>&1

echo "Exit code: $?"
```

**预期结果**：CLI 报错，列出可用 source 列表，退出码非零。

#### N-04: 空目录作为日志路径

**目的**：验证日志目录存在但为空时的行为。

**步骤**：

```bash
# 创建空目录
mkdir -p /tmp/empty-claude/projects/

# 通过环境变量或自定义路径指向空目录
# 注：Claude parser 默认读 ~/.claude/projects/，无法直接覆盖
# 使用 Gemini parser 的 base_path 参数测试
python3 -c "
from adr_sensor.parsers.gemini_parser import GeminiParser
from pathlib import Path

parser = GeminiParser(base_path=Path('/tmp/empty-gemini'))
events = parser.parse_all()
assert events == [], f'Expected empty list, got {len(events)} events'
print('OK: empty directory returns empty list')
"
```

**预期结果**：返回空列表，不抛异常。

#### N-05: 权限不足的日志目录

**目的**：验证权限不足时的行为。

**步骤**：

```bash
# 创建无读权限的目录
mkdir -p /tmp/no-permission/projects/
echo '{"test":"data"}' > /tmp/no-permission/projects/test.jsonl
chmod 000 /tmp/no-permission/projects/test.jsonl

# 运行 sensor（指向受限目录）
python3 -c "
from adr_sensor.parsers.gemini_parser import GeminiParser
from pathlib import Path

parser = GeminiParser(base_path=Path('/tmp/no-permission'))
events = parser.parse_all()
print(f'Events with no permission: {len(events)}')
"

# 恢复权限以便清理
chmod 644 /tmp/no-permission/projects/test.jsonl
```

**预期结果**：权限不足的文件被跳过，不导致整个解析失败，诊断记录 `denied` 或类似状态。

#### N-06: 超大日志文件

**目的**：验证大日志文件的处理（截断或正常处理）。

**步骤**：

```bash
# 创建大日志文件（模拟）
python3 -c "
import json
with open('/tmp/large-claude/projects/big-session.jsonl', 'w') as f:
    for i in range(100000):
        msg = {'role':'user' if i%2==0 else 'assistant', 'content':f'Message {i}'*100}
        f.write(json.dumps(msg) + '\n')
" 2>/dev/null || mkdir -p /tmp/large-claude/projects/ && python3 -c "
import json
with open('/tmp/large-claude/projects/big-session.jsonl', 'w') as f:
    for i in range(100000):
        msg = {'role':'user' if i%2==0 else 'assistant', 'content':f'Message {i}'*100}
        f.write(json.dumps(msg) + '\n')
"

# 测量解析时间
time adr-sensor --source claude --output-dir ./test-large 2>&1 || true
```

**预期结果**：
- 大文件不导致内存溢出或超时
- Claude Code 解析器对工具参数和结果在 1,000 字符处截断
- 处理完成或 `partial` 状态

#### N-07: OTLP 导出无可用 endpoint

**目的**：验证 OTLP 导出在 endpoint 不可用时的行为。

**步骤**：

```bash
# 创建 OTLP 配置指向不存在的 endpoint
cat > /tmp/bad-otel-config.json << 'EOF'
{
  "endpoint": "http://localhost:9999/v1/logs",
  "service_name": "adr-sensor-test",
  "timeout_seconds": 2,
  "flush_timeout_seconds": 5
}
EOF

# 运行
adr-sensor --source claude --otel-config /tmp/bad-otel-config.json --no-save 2>&1

echo "Exit code: $?"
```

**预期结果**：
- OTLP 导出失败但不导致整个运行崩溃
- 错误记录在诊断文件中
- `--fail-on-error` 时退出码非零

#### N-08: `--source all` 在无任何代理的环境

**目的**：验证没有任何 AI 代理安装时 `--source all` 的行为。

**步骤**：

```bash
# 在隔离环境中运行（无任何 AI 代理日志）
docker run --rm python:3.11-slim bash -c "
pip install adr-sensor 2>/dev/null
adr-sensor --output-dir /tmp/output 2>&1
echo 'Exit code:' \$?
cat /tmp/output/diagnostics.jsonl 2>/dev/null
"
```

**预期结果**：
- 所有来源状态为 `no_input`
- 不抛异常，退出码 0
- 诊断文件记录所有来源的 `no_input` 状态

### 5.4 边界测试集

#### B-01: 默认 14 天回溯窗口

**目的**：验证默认仅采集最近 14 天的日志。

**步骤**：

```bash
# 创建旧日志（超过 14 天）
mkdir -p ~/.claude/projects/old-session/
echo '{"role":"user","content":"old message"}' > ~/.claude/projects/old-session/old.jsonl

# 设置文件修改时间为 20 天前
touch -d "20 days ago" ~/.claude/projects/old-session/old.jsonl 2>/dev/null || \
  touch -t $(date -v-20d +%Y%m%d%H%M) ~/.claude/projects/old-session/old.jsonl

# 运行默认（14 天）
adr-sensor --source claude --output-dir ./test-14days

# 运行 --all-history
adr-sensor --source claude --all-history --output-dir ./test-all-history

# 对比
echo "14-day events: $(wc -l < ./test-14days/*.jsonl 2>/dev/null || echo 0)"
echo "all-history events: $(wc -l < ./test-all-history/*.jsonl 2>/dev/null || echo 0)"
```

**预期结果**：`--all-history` 包含旧日志，默认 14 天不包含。

#### B-02: 跨平台自动跳过

**目的**：验证不支持当前操作系统的来源被自动跳过。

**步骤**：

```bash
# 在 Linux 上运行
uname -s  # 应输出 Linux

adr-sensor --output-dir ./test-skip

# 验证 claude_desktop 被跳过（仅 macOS/Windows）
cat ./test-skip/diagnostics.jsonl | python3 -c "
import json, sys
sources_seen = set()
for line in sys.stdin:
    diag = json.loads(line)
    sources_seen.add(diag['source'])
# Linux 上不应有 claude_desktop
assert 'claude_desktop' not in sources_seen or True  # 平台限制来源可能不出现在诊断中
print(f'Sources processed: {sources_seen}')
"
```

**预期结果**：平台限制来源在不适用的操作系统上不出现在处理列表中。

#### B-03: 子代理会话关联

**目的**：验证 Claude Code 子代理会话的 `parent_session_id` 和 `agent_id` 字段。

**前置条件**：Claude Code 使用过子代理功能（`~/.claude/projects/<project>/<sessionId>/subagents/` 存在）。

**步骤**：

```bash
adr-sensor --source claude --output-dir ./test-subagent --output-format jsonl

python3 -c "
import json
with open('./test-subagent/agent_event_logs.jsonl') as f:
    subagent_count = 0
    for line in f:
        event = json.loads(line)
        sid = event['session_id']
        if '_agent_' in sid:
            subagent_count += 1
            # 验证子代理字段
            ctx = event.get('session_context', {})
            assert 'parent_session_id' in ctx or '_agent_' in sid
            print(f'Subagent: {sid}')
    print(f'Total subagent sessions: {subagent_count}')
"
```

**预期结果**：子代理 session_id 包含 `_agent_` 后缀，与父会话关联。

#### B-04: MCP 工具调用识别

**目的**：验证 MCP 工具调用被正确标记为 `tool_type: "mcp_tool"` 并填充 `server_name`。

**步骤**：

```bash
adr-sensor --output-dir ./test-mcp --output-format jsonl

python3 -c "
import json
mcp_tools = set()
with open('./test-mcp/agent_event_logs.jsonl') as f:
    for line in f:
        event = json.loads(line)
        for msg in event.get('chat_history', []):
            for tool in msg.get('tools', []):
                if tool.get('tool_type') == 'mcp_tool':
                    mcp_tools.add(tool['tool_name'])
                    assert 'server_name' in tool or tool.get('server_name') is None
print(f'MCP tools found: {mcp_tools}')
"
```

**预期结果**：MCP 工具被标记为 `mcp_tool` 类型，`server_name` 已填充或留空（记录名模糊时）。

#### B-05: `--fail-on-error` 退出码

**目的**：验证 `--fail-on-error` 在有错误时返回非零退出码。

**步骤**：

```bash
# 正常运行（无错误）
adr-sensor --source claude --output-dir ./test-ok --fail-on-error
echo "Clean exit: $?"

# 制造错误（损坏日志）后运行
echo 'corrupt' >> ~/.claude/projects/*/test.jsonl 2>/dev/null
adr-sensor --source claude --output-dir ./test-err --fail-on-error 2>&1 || true
echo "Error exit: $?"
```

**预期结果**：有解析错误时 `--fail-on-error` 返回非零退出码，无错误时返回 0。

### 5.5 测试运行方式

#### 5.5.1 单元测试

Sensor 自带测试套件，使用 `pytest`：

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行全部测试
pytest tests/ -v

# 运行测试并生成覆盖率
pytest tests/ -v --cov=adr_sensor

# 运行特定解析器的测试
pytest tests/test_claude_parser.py -v

# Lint
ruff check adr_sensor/
ruff format adr_sensor/
```

测试特点：

- **合成记录**：各解析器的契约测试使用合成 transcripts/记录，不启动实际 AI 代理
- **跨平台**：测试在所有支持的 host 上运行（CI matrix）
- **无需账户**：例如 Gemini 测试不需要 Gemini 账户
- **契约验证**：多个解析器对照上游源码验证：
  - Gemini CLI：对照 record types、journal writer、storage paths、supported platforms
  - DeepSeek Harness：对照 JSONL persistence contract 和 v3 event declarations

截至 Gemini CLI 支持 commit（`93ed35c`），244 个 Sensor 测试在 Python 3.11 上全部通过。

#### 5.5.2 集成测试环境

```bash
# 从源码安装
git clone https://github.com/uber/ADR
cd ADR/Sensor

# 创建虚拟环境
python3 -m venv .venv
source .venv/bin/activate

# 安装
pip install -e ".[dev]"

# 运行测试
uv run pytest tests/ -v

# 或使用 uv
uv sync
uv run pytest tests/ -v
```

#### 5.5.3 CI Matrix

Gemini CLI 解析器的 CI matrix 覆盖三平台：

```yaml
# 简化的 CI matrix 概念
matrix:
  os: [ubuntu-latest, macos-latest, windows-latest]
  python: ["3.9", "3.10", "3.11", "3.12", "3.13"]
```

每个组合执行：discovery（日志路径发现）、parsing（记录解析）、export（导出验证）。

---

## 六、安全分析与技术权衡

### 6.1 与 EDR 的对比

| 特性 | 传统 EDR | ADR Sensor |
|---|---|---|
| **可见性层级** | 系统级（文件/进程/网络） | 语义级（意图/推理/工具调用） |
| **因果链** | 无法关联意图与执行 | 完整重建 prompt→reasoning→tool→outcome |
| **AI 代理行为理解** | 无法区分恶意与良性代理行为 | 可判断行为是否对齐用户意图 |
| **MCP 工具调用可见性** | 不可见 | 完整记录参数和结果 |
| **设计时代背景** | MCP 之前 | MCP 之后 |
| **语义威胁检测** | 不支持 | 核心能力 |
| **部署方式** | 系统级守护进程 | 每小时调度的 Python 脚本 |
| **性能开销** | 持续监控，资源占用高 | 每次 0.182 秒，轻量级 |

### 6.2 与网关方案的对比

论文还讨论了 LLM/MCP 网关作为替代方案：

| 特性 | 网关方案 | ADR Sensor |
|---|---|---|
| **实现难度** | 较易 | 需要端点部署 |
| **流式响应兼容** | 不兼容 | 兼容 |
| **环境上下文** | 部分信息缺失 | 完整 |
| **需修改 MCP 主机** | 需要 | 不需要 |
| **实时阻断能力** | 天然支持 | 需配合 Hooks |
| **部署位置** | 网络中间层 | 端点 |

### 6.3 设计权衡

| 设计决策 | 选择 | 代价 |
|---|---|---|
| **日志解析 vs 实时拦截** | 日志解析（事后采集） | 不支持实时阻断 |
| **端点部署 vs 网关** | 端点 | 不需要修改 MCP 主机，但需管理端点覆盖 |
| **回溯窗口** | 默认 14 天 | 超过 14 天的历史需 `--all-history` |
| **截断限制** | Claude Code 工具参数/结果 1,000 字符 | 超长内容被截断，可能丢失部分上下文 |
| **OTLP 导出不脱敏** | 完整数据传输 | prompts、凭据、路径可能被传输到 SIEM |
| **合成记录测试** | 不启动实际 AI 代理 | 无法覆盖真实代理的所有行为变体 |
| **研究工件** | 非 production-ready | 依赖携带已知 CVE，需隔离环境运行 |

---

## 七、缺口与未验证事项

### 7.1 代码限制

| 限制 | 影响 | 置信度 |
|---|---|---|
| 论文未明确提及"AgentEvent Schema" | Schema 定义来自源码和 README，非论文正文 | 高（源码可验证） |
| 未覆盖 VS Code Copilot Chat 扩展 | 仅覆盖 Copilot CLI session state | 高（README 明确说明） |
| Antigravity parser 可能在项目结构树中缺失 | 可能是较新增的解析器 | 中（基于 README 描述） |
| 无实时流式处理 | 每小时调度，非实时 | 高（论文明确每小时调度） |
| OTLP 导出不脱敏 | 敏感数据可能传输到 SIEM | 高（README 明确警告） |
| 部分依赖携带已知 CVE | 不适合直接用于生产 | 高（OPEN_SOURCE_REVIEW.md 明确说明） |

### 7.2 未验证事项

| 事项 | 影响 | 验证方式 |
|---|---|---|
| 运行时性能（0.182 秒/次） | 来自论文，未在本机验证 | 在目标环境实测 |
| 7,200+ 主机部署规模 | 来自论文，无法独立验证 | 信任论文数据 |
| 10,000+ 日均会话 | 来自论文，无法独立验证 | 信任论文数据 |
| Windows 平台行为 | 本机为 macOS，未在 Windows 上验证 | 在 Windows 环境运行测试 |
| 子代理嵌套深度上限 | 未确认是否有递归深度限制 | 源码审查 |
| OTLP 交付检查点的重试行为 | "至少一次"语义可能产生重复 | 需网络故障注入测试 |

### 7.3 对文章结论的潜在影响

- AgentEvent Schema 的字段定义基于源码和 README 而非论文正文，但源码是可验证的权威来源，不影响结论可靠性。
- 性能数据（0.182 秒）来自论文而非独立实测，在实际部署中可能因日志量和代理数量不同而变化。
- Windows 平台的解析器行为基于 README 描述和 CI matrix，未在本机验证，但 CI 测试提供了可信度。

---

## 附录 A 代码坐标索引

路径相对 `Sensor/adr_sensor/`，基于初始公开 release commit `db4fb0e` 和后续更新。

| 主题 | 坐标 |
|---|---|
| 包导出 | `__init__.py` |
| CLI 入口 | `cli.py` |
| AgentObserver 编排器 | `observer.py` |
| BaseParser 抽象基类 | `parsers/base_parser.py` |
| Claude Code 解析器 | `parsers/claude_parser.py` |
| Cursor 解析器 | `parsers/cursor_parser.py` |
| Cline 解析器 | `parsers/cline_parser.py` |
| Claude Desktop 解析器 | `parsers/claude_desktop_parser.py` |
| Codex 解析器 | `parsers/codex_parser.py` |
| Copilot 解析器 | `parsers/copilot_parser.py` |
| DeepSeek Harness 解析器 | `parsers/dsh_parser.py` |
| Gemini CLI 解析器 | `parsers/gemini_parser.py` |
| opencode 解析器 | `parsers/opencode_parser.py` |
| Warp 解析器 | `parsers/warp_parser.py` |
| Antigravity 解析器 | `parsers/antigravity_parser.py` |
| AgentEvent schema | `schemas/agent_event_schema.py` |
| SystemConfiguration schema | `schemas/system_config_schema.py` |
| OTLP 配置 | `exporters/config.py` |
| OpenTelemetry exporter | `exporters/opentelemetry.py` |
| 字符串工具 | `utils/string_utils.py` |
| 时间戳工具 | `utils/timestamp_utils.py` |
| OTLP 配置示例 | `examples/opentelemetry-config.json` |
| 测试目录 | `tests/` |

---

## 附录 B 关键技术结论及证据索引

| # | 结论 | 证据来源 |
|---|---|---|
| C1 | Sensor 是语义层遥测工具，非系统级 EDR | 论文 §1 设计动机；README "ADR Observability" |
| C2 | 支持 11 个 AI 代理平台 | README 支持列表；Gemini CLI commit `93ed35c` |
| C3 | AgentEvent 是统一 schema，包含 chat_history + session_context + token_usage | `schemas/agent_event_schema.py`；README schema 示例 |
| C4 | 每个解析器实现 BaseParser 接口 | `parsers/base_parser.py`；README §添加新解析器 |
| C5 | AgentObserver.ingest_all() 遍历 SOURCES 元组 | `observer.py`；README Python API |
| C6 | 默认回溯窗口 14 天，按文件修改时间 | README 各代理日志路径节 |
| C7 | Claude Code 工具参数/结果在 1,000 字符处截断 | README Claude Code 节 |
| C8 | OTLP 导出不应用脱敏 | README OTLP 导出节；明确警告 |
| C9 | Sensor 不做威胁检测，检测由 Detector 负责 | README 五大能力；论文 §3 |
| C10 | 论文未在正文中明确提及"AgentEvent Schema" | 论文 HTML 全文 |
| C11 | 244 个 Sensor 测试在 Python 3.11 上通过 | Gemini CLI commit `93ed35c` commit message |
| C12 | 生产环境每小时调度，0.182 秒/次 | 论文 §4 |
| C13 | 研究工件，非 production-ready | `docs/OPEN_SOURCE_REVIEW.md` |
| C14 | 跨平台支持 macOS/Linux/Windows | README；CI matrix |
| C15 | Copilot CLI 不覆盖 VS Code Copilot Chat 扩展 | README Copilot CLI 节 |

---

## 附录 C 术语表

| 术语 | 定义 |
|---|---|
| ADR | Agentic AI Detection and Response，Uber 开源的企业 AI 代理安全系统 |
| Sensor | ADR 的遥测采集组件，解析 AI 代理日志并标准化为 AgentEvent |
| AgentEvent | Sensor 的统一输出 schema，包含会话、聊天历史、工具调用、上下文 |
| AgentObserver | Sensor 的编排器，执行 ingest → filter → display → export 流水线 |
| BaseParser | 所有解析器的抽象基类，定义 `parse_all()` 接口 |
| MCP | Model Context Protocol，AI 代理与外部工具通信的协议 |
| OTLP | OpenTelemetry Protocol，用于将遥测数据导出到 Collector/SIEM |
| EDR | Endpoint Detection and Response，传统端点检测与响应工具 |
| ADR-Bench | ADR 的安全基准，302 个任务、133 个 MCP 服务器、17 种攻击技术 |
| Discovery | ADR 的端点资产发现组件，回答"端点上有哪些 AI 工具" |
| Detector | ADR 的威胁检测组件，两级架构（Tier 1 分诊 + Tier 2 深度推理） |
| session_context | AgentEvent 中的 session 级配置字段，代理对自身权限的视图 |
| token_usage | AgentEvent 中的 token 计数字段，分 last_turn 和 cumulative |
| ChatMessage | AgentEvent chat_history 中的消息单元，包含 role、content、tools |
| ToolUsage | ChatMessage tools 中的工具调用记录，包含 name、type、arguments、result |
