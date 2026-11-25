# 蜜罐如何识别 Agent 指纹 — AgentCapture 源码专题

> 版本锚定：`Tcotl/AgentCapture`，源码快照 `728ffa0`（2026-11-12，v0.7.0）。本文所有行号以该快照为准。组件总览见 [source-notes.md](source-notes.md)。配套专题：[蜜罐提示词注入实操](prompt-injection.md)。

AgentCapture 的指纹识别是**两层结构**：风险引擎回答「是不是 Agent」（打分、给处置建议），产品签名库回答「是哪个 Agent」（给产品名、版本、置信度、证据链）。两层独立维护、互相不依赖，最终都汇入事件流。本文拆解这两层的全部规则表、匹配算法、实测表现与口径差异。

## 目录

- [一、两层指纹的分工](#一两层指纹的分工)
- [二、第一层：风险引擎的 Agent 信号](#二第一层风险引擎的-agent-信号)
  - [2.1 UA 词表与计分](#21-ua-词表与计分)
  - [2.2 请求头线索与「缺人类头」启发式](#22-请求头线索与缺人类头启发式)
  - [2.3 汇总打分与分档](#23-汇总打分与分档)
- [三、第二层：产品级签名库（31 条）](#三第二层产品级签名库31-条)
  - [3.1 签名全表](#31-签名全表)
  - [3.2 匹配算法与置信度](#32-匹配算法与置信度)
  - [3.3 版本提取](#33-版本提取)
- [四、第三层：行为序列指纹](#四第三层行为序列指纹)
- [五、指纹在处置链中的用途](#五指纹在处置链中的用途)
- [六、实测（macOS 本机）](#六实测macos-本机)
- [七、口径差异与局限](#七口径差异与局限)
- [附录 A 代码坐标索引](#附录-a-代码坐标索引)
- [附录 B 关键结论及证据索引](#附录-b-关键结论及证据索引)

---

## 一、两层指纹的分工

代码自己的注释把这个分工讲得很清楚（`app/services/agent_fingerprint.py:1-11`）：

> The risk engine only answers "is this an agent?" (UA markers, header clues). This module answers "which agent is it?" — a product-level signature registry matched against User-Agent plus distinctive request headers, returning a confidence score and the evidence that fired so operators can audit the call.

| 层 | 模块 | 输入 | 输出 | 用途 |
|---|---|---|---|---|
| 第一层 | `app/services/risk_engine.py::classify_http_request` | UA、请求头、路径、payload、频率 | 分数 + 信号名 + 五级决策 | 处置（challenge/isolate/block） |
| 第二层 | `app/services/agent_fingerprint.py::identify_from_headers` | UA + 特征请求头 | 产品 key/label/vendor/kind + 置信度 + 证据链 | 归因标注（事件 payload、告警） |
| 第三层 | `app/services/counter_intel.py::classify_behavior` | 会话请求历史（路径 + 时间戳） | automation_like / human_like + 分数 | 无 UA 伪装时的兜底信号 |

注意还有一个更粗的 `app/services/agent_injection.py::detect_agent_type`（六值枚举，L343-362），它只服务于「要不要注入指令」的判断（详见[注入专题](prompt-injection.md)第二节），不参与风险打分。

## 二、第一层：风险引擎的 Agent 信号

### 2.1 UA 词表与计分

`app/services/risk_engine.py` 里有两张 UA 词表，计分不同：

**`SUSPICIOUS_UA_MARKERS`（22 条，L7-30）——「可疑客户端」，+30 分**：curl、wget、python-requests、python-urllib、aiohttp、httpx、go-http-client、okhttp、sqlmap、nikto、nuclei、dirsearch、ffuf、gobuster、wfuzz、zgrab、nmap、masscan、playwright、puppeteer、headlesschrome、browser-use。

**`AGENT_UA_MARKERS`（33 条，L32-76）——「Agent 客户端」，+40 分**：

| 分组 | 条目 |
|---|---|
| 浏览器自动化（4） | browser-use、playwright、puppeteer、headlesschrome |
| 通用 Agent/LLM 关键词（8） | chatgpt、claude、gpt-4、llm、ai-agent、langchain、crewai、autogpt |
| 编码 Agent CLI（12） | codex、opencode、gemini、google-genai、kimi、moonshot、cursor、aider、cline、windsurf、codebuddy、junie |
| 渗透测试 Agent 框架（9） | hexstrike、strix、pentagi、pentestagent、pentest-agent、artex、cyberstrikeai、slingshoot、sapper |

两张表有两个刻意的设计立场，都写在注释里：

1. **copilot 有意排除**（L53-56）：「editor-autocomplete UAs are not attack agents」——有外部报告者反馈了误报，Copilot 流量仍会被第二层打上产品标签，但不计为攻击分数。
2. **渗透框架有意计入**（L63-66）：「the platform's exact capture targets, so their own UAs score as agent traffic (opposite of the copilot case above)」——hexstrike 注明是对 2026-11 演练流量的实测验证，其余为产品名标记。

另外 UA **完全缺失** +20 分（L172-174）。

### 2.2 请求头线索与「缺人类头」启发式

- `AGENT_HEADER_CLUES`（5 条，L78-84）：出现任一 `x-openai` / `x-anthropic` / `x-langfuse` / `x-agent` / `x-automated` 头，+25 分。
- `MISSING_HUMAN_HEADERS`（4 项，L86）：真实浏览器会带的 `sec-fetch-site`、`sec-fetch-mode`、`sec-fetch-dest`、`accept-language`。**缺其中 ≥2 项** +15 分。这是一条与 UA 无关的兜底启发式——UA 伪装成 Chrome 但不带 sec-fetch 系列头的客户端仍会被抬分。
- Payload 检查（L98-142）：4 组正则（路径穿越 / SQL 注入 / XSS / 命令注入），对 URL 解码后的 path+query 匹配，每命中一组 +25 分。注释明确说明 pattern 收得很紧以压误报。

### 2.3 汇总打分与分档

`classify_http_request`（L157-248）把上述信号与频率信号合并：

| 信号 | 条件 | 分数 |
|---|---|---|
| missing_user_agent | UA 为空 | +20 |
| suspicious_user_agent | 命中 22 条词表 | +30 |
| ai_agent_ua_detected | 命中 33 条词表 | +40 |
| ai_agent_header_detected | 命中 5 条特征头 | +25 |
| missing_human_headers | 缺 ≥2 个人类头 | +15 |
| trap_route_hit | 命中 `/archive/`、`/d/` 蜜饵路由 | +45 |
| high_signal_path_hit | 命中 3 条高信号路径 | +35 |
| payload 规则（4 组） | 每组 | +25 |
| **prompt_canary_echo** | **回显注入的 canary token** | **+70** |
| high/elevated_request_velocity | 会话或 IP 近期事件 ≥12 / ≥6 | +20 / +10 |
| challenge_evasion | 收到 ≥3 次 challenge 仍继续 | +30 |
| write_attempt_after_detection | 写方法 + 蜜饵/canary 命中 | +25 |

分档（L237-246）：**≥95 block / ≥70 isolate / ≥45 challenge / ≥20 observe / 其余 allow**。

执行前提要注意：这些决策只在**管理平面 + Guard 模式**强制执行；蜜罐平面（48777）挂的是 `observe_only_all=True` 的同一中间件，只记录不处置（见总览笔记 §1.2）。canary 回显 +70 是唯一无条件落库隔离的信号（`app/middleware/injector.py:186-193`），详见[注入专题](prompt-injection.md)第六节。

## 三、第二层：产品级签名库（31 条）

### 3.1 签名全表

`app/services/agent_fingerprint.py::AGENT_SIGNATURES`（L18-248）共 **31 条签名**，按 `kind` 分 5 组。每条签名的字段：`ua_markers`（强标记，命中即 0.9）、`ua_weak_markers`（弱标记，0.6）、`ua_prefixes`（前缀，0.75）、`header_markers`（特征头名，存在即加分）、`header_pairs`（头名+值对，加分更多）。

**coding_agent（14 条）**

| key | label | vendor | 强 UA 标记 | 弱 UA / 其他信号 |
|---|---|---|---|---|
| claude_code | Claude Code | Anthropic | claude-cli, claude-code, claudecode | 弱：claude；头：anthropic-client, anthropic-beta, x-stainless-organization |
| codex | ChatGPT Codex | OpenAI | codex_cli_rs, codex_cli, codex/ | 弱：codex；对：originator=codex；头：openai-beta |
| opencode | OpenCode | OpenCode | opencode | — |
| kimi_code | Kimi Code | Moonshot AI | kimi-cli, kimicode, kimi-code, kimicli | 弱：kimi, moonshot |
| pi | Pi | Pi | pi-agent, pi/cli, pi-agent-cli | 前缀：pi/ |
| zcode | ZCode | ZCode | zcode, z-code | — |
| gemini_cli | Gemini CLI | Google | gemini-cli, google-genai | 弱：gemini |
| copilot | GitHub Copilot | GitHub | github-copilot, copilot | — |
| cursor | Cursor | Anysphere | cursor | — |
| aider | Aider | Aider | aider | — |
| cline | Cline | Cline | cline | — |
| windsurf | Windsurf | Codeium | windsurf, codeium | — |
| codebuddy | CodeBuddy | Tencent | codebuddy | — |
| junie | Junie | JetBrains | junie | — |

**assistant（1 条）**：chatgpt（ChatGPT / OpenAI）——ua_markers 含 chatgpt-user、chatgpt、gptbot、oai-searchbot。

**automation（3 条）**：browser-use、playwright（Microsoft）、puppeteer（Google，含 headlesschrome）。

**framework（11 条）**：langchain、crewai、autogpt、以及 2026-11 新增的 8 个渗透框架 hexstrike / strix / pentagi / pentestagent / slingshoot / artex / cyberstrikeai / sapper（L174-176 注释：hexstrike 经演练流量验证，其余为产品名标记，「these are the platform's targets」）。sapper 另有弱标记 n1neman。

**api_sdk（2 条）**：openai_sdk（openai-python/openai-node/openai-go）、anthropic_sdk（anthropic-python/anthropic-typescript/anthropic-sdk）。

模块 docstring（L8-10）注明：claude code / codex / opencode / kimi / pi / zcode 六个是对 2026-08 反招募轮次**真实流量验证**过的，其余用产品规范 UA。

### 3.2 匹配算法与置信度

`identify_from_headers`（L267-333）遍历全部签名，取**置信度最高的一个**（L330-331）。计分规则（L284-316）：

| 信号 | 置信度 |
|---|---|
| 强 UA 标记命中 | **0.90** |
| 弱 UA 标记命中 | **0.60** |
| UA 前缀命中 | **0.75** |
| 特征头存在 | `max(confidence, 0.65) + 0.03` |
| 头名+值对命中 | `max(confidence, 0.75) + 0.05` |
| 上限 | 0.98 |

也就是说：单一强 UA 命中 = 0.90；强 UA + 两个特征头 = 0.96；UA 完全不伪装、只带 `openai-beta` 头也能拿到 0.65+ 的底线判定。所有命中的证据逐条记入 `evidence` 列表（如 `ua: codex_cli_rs`、`header: originator=codex`），运维可在事件详情里审计这条判定为什么成立——这是该模块区别于「裸正则」的核心设计。

### 3.3 版本提取

`_version_pattern`（L253-259）对命中的标记后跟的版本号做提取：正则 `marker[/ v]?(\d+(?:\.\d+)+...)`（忽略大小写，截断 32 字符）。实测 `codex_cli_rs/0.9.0` 提取出 `version: "0.9.0"`。

## 四、第三层：行为序列指纹

当攻击者把 UA 改成正常浏览器时，前两层失效，`app/services/counter_intel.py::classify_behavior`（L138-176）用会话请求历史兜底。每 N 次请求（默认第 5 次）触发一次分类（`app/middleware/injector.py:517-527`），取会话最近 11 条事件加当前请求，计算 4 个信号：

| 信号 | 条件 | 分数 |
|---|---|---|
| no_static_assets | 静态资源占比 <5% 且路径数 ≥4 | +30 |
| high_path_diversity | 去重路径比 >0.9 且路径数 ≥5 | +25 |
| uniform_intervals | 请求间隔变异系数倒数 >0.75（匀速） | +25 |
| sustained_sequenced_requests | 路径数 ≥10 且静态占比 <10% | +20 |

分数 ≥50（可配）判 `automation_like`，写入事件 `payload_json.behavior` 并附加 `behavior_automation` 信号；≥75 附加 `behavior_automation_strong`（`injector.py:546-551`）。阈值在管理台「行为序列指纹」面可调（`app/services/surface_config.py:248-253`：min_events 5 / classify_every 5 / auto 50 / strong 75）。

注意分类是**按会话**聚合的：不带 cookie 的客户端每个请求都是新会话，历史永远凑不够 min_events，行为指纹不生效——对无状态工具真正起作用的是按 IP 聚合的 velocity 信号（§2.3）。

## 五、指纹在处置链中的用途

1. **事件归因**：每个请求落库时跑 `identify_from_headers`，命中则写 `payload_json.agent_fingerprint` 并附加 `agent_product:<key>` 信号（`injector.py:473-479`）。攻击者画像按 agent_products 聚合打「AI Agent」标签（`counter_intel.py::attacker_tags`）。
2. **隔离短路响应**：已隔离来源再访问时，隔离页的记录事件里带完整指纹（`injector.py:274-281`）。
3. **阻断页**：block 决策若由 agent 信号触发，页面直接报出检测到的 agent 类型（`injector.py:196-202` + `agent_injection.py::generate_block_page`）。
4. **蜜饵内容个性化**：AGENTS.md 蜜饵读取事件的 payload 里记录 `agent_product` 的 label（`app/routes/counter_offense.py:47-49,122-129`）。
5. **风险加分**：第一层的 `ai_agent_ua_detected` / `ai_agent_header_detected` 信号直接抬分触发处置。

## 六、实测（macOS 本机）

环境：本机跑管理面 4877 + 蜜罐面 48777（全新数据库）。

**产品指纹命中**——用 Codex CLI 的真实请求形态访问 `/AGENTS.md`：

```bash
curl http://127.0.0.1:48777/AGENTS.md \
  -A "codex_cli_rs/0.9.0 (Mac OS 15.5; arm64) Codex" \
  -H "originator: codex" -H "openai-beta: responses=v1"
```

事件 payload（sqlite `events` 表实测）：

```json
{"agent_fingerprint": {"key": "codex", "label": "ChatGPT Codex",
  "vendor": "OpenAI", "kind": "coding_agent", "confidence": 0.98,
  "version": "0.9.0",
  "evidence": ["ua: codex_cli_rs", "header: openai-beta", "header: originator=codex"]}}
```

同一请求的风险层信号：`ai_agent_ua_detected`（+40）+ `missing_human_headers`（+15）= 55 分 → challenge 档（蜜罐面只记录不处置）。UA 词表同时命中了第二层的 `codex` 和第一层的 `ai_agent_ua_detected`，两层独立工作。

**行为序列指纹命中**——同一会话（带 cookie）匀速连拉 6 页毒化数据集：

```bash
for i in 1..6: curl -b jar "http://127.0.0.1:48777/portal/api/dataset?page=$i"
```

第 5 次请求触发分类，事件实测：

```json
{"behavior": {"score": 50, "classification": "automation_like",
  "signals": ["no_static_assets", "sustained_sequenced_requests"]}}
```

信号 `behavior_automation` 附加成功（risk 95，与 velocity/challenge_evasion 叠加后到 block 档）。注意第 6 次请求因「匀速」未命中（间隔 1s 整数抖动）和路径多样性不足，score 停在 50 而非更高。

## 七、口径差异与局限

1. **README 写 23，代码是 31**：`README.md:63` 与 `README.md:130` 均写「23 product-level fingerprints」，实际 `AGENT_SIGNATURES` 为 31 条（L18-248 逐条清点）。差异来自 2026-11 新增的 8 个渗透测试框架签名——README 未随代码更新。
2. **UA 可伪造**：整套第一、二层都是明文 UA/头匹配，改一个 UA 字符串即可绕过；真正的对抗纵深在 canary 回显（+70、无条件落库）与行为序列兜底。
3. **弱标记误报面**：`claude`、`gemini`、`kimi`、`codex` 等弱标记是普通子串匹配（0.6 置信度），UA 里带这些词的非 agent 工具会被误标——但弱标记不进风险词表（风险词表是独立维护的 33 条），所以误标只影响归因不影响处置。
4. **行为指纹按会话聚合**：无 cookie 客户端不触发（§四），这是设计取舍（依赖 IP 级 velocity 补位），不是 bug。
5. **签名维护是手工清单**：新 Agent 需要改代码加签名；没有热加载或远程下发机制。

## 附录 A 代码坐标索引

| 内容 | 坐标 |
|---|---|
| 模块定位注释 | app/services/agent_fingerprint.py:1-11 |
| 31 条签名表 | app/services/agent_fingerprint.py:18-248 |
| 版本提取正则 | app/services/agent_fingerprint.py:253-259 |
| 匹配主函数与置信度 | app/services/agent_fingerprint.py:267-333 |
| 可疑 UA 词表（22） | app/services/risk_engine.py:7-30 |
| Agent UA 词表（33）+ copilot/渗透框架注释 | app/services/risk_engine.py:32-76 |
| 特征头 / 缺人类头 | app/services/risk_engine.py:78-86 |
| payload 正则 4 组 | app/services/risk_engine.py:98-142 |
| 打分主函数与分档 | app/services/risk_engine.py:157-248 |
| 行为分类算法 | app/services/counter_intel.py:138-176 |
| 行为分类注入点（每 N 次请求） | app/middleware/injector.py:490-551 |
| 指纹写入事件 payload | app/middleware/injector.py:473-479 |
| 隔离短路带指纹 | app/middleware/injector.py:274-281 |
| 行为面配置默认值 | app/services/surface_config.py:248-253 |
| AGENTS.md 事件带 agent_product | app/routes/counter_offense.py:47-49,111-160 |
| README 23 条口径 | README.md:63、README.md:130 |
| 粗粒度六值枚举 detect_agent_type | app/services/agent_injection.py:343-362 |

## 附录 B 关键结论及证据索引

| # | 结论 | 证据 |
|---|---|---|
| B1 | 指纹识别为三层结构：风险引擎（是否 Agent）→ 产品签名库（哪个 Agent）→ 行为序列（UA 伪装时兜底） | agent_fingerprint.py:1-11（模块注释原文）；risk_engine.py:157-248；counter_intel.py:138-176 |
| B2 | 产品签名库实际 31 条（coding_agent 14 / assistant 1 / automation 3 / framework 11 / api_sdk 2），README 写 23 未更新 | agent_fingerprint.py:18-248 逐条清点；README.md:63 |
| B3 | 置信度算法：强 UA 0.9 / 弱 0.6 / 前缀 0.75，特征头 +0.03（底 0.65）、头值对 +0.05（底 0.75），封顶 0.98；证据链逐条记录 | agent_fingerprint.py:284-316 |
| B4 | copilot 从风险词表有意排除（误报反馈），渗透框架 UA 有意计入（明确目标）；两者立场相反、注释均明示理由 | risk_engine.py:53-66 |
| B5 | 风险分档 ≥95 block / ≥70 isolate / ≥45 challenge / ≥20 observe；canary 回显 +70 是最高单一信号 | risk_engine.py:237-246、206-208 |
| B6 | 实测：codex_cli_rs UA + originator/openai-beta 头 → 置信度 0.98、版本 0.9.0、三条证据；风险 55 challenge | 本文第六章实测输出（events 表 payload_json） |
| B7 | 实测：同会话 6 连击第 5 次触发行为分类，score 50 automation_like（no_static_assets + sustained_sequenced_requests） | 本文第六章实测输出（payload_json.behavior） |
| B8 | 行为指纹按会话聚合，无 cookie 客户端不生效；无状态工具依赖 IP 级 velocity | injector.py:509-527（按 session_id 查询）；risk_engine.py:210-218（注释明示） |
