# 蜜罐识别 Agent 指纹的实施方案

> 本文是一份可直接落地的实施指南：给出蜜罐/防线上识别 AI Agent 的三层指纹方案（是否 Agent → 哪个 Agent → 是否自动化行为），每层附可直接复用的规则表、算法与验证清单。所有设计点均经过开源参考实现 **AgentCapture**（快照 `728ffa0`，2026-11-12，v0.7.0）源码核验与本机实测（macOS，2026-11-25），代码坐标集中在附录 A，证据链见附录 B。

## 目录

- [一、方案总览：为什么要三层](#一方案总览为什么要三层)
- [二、第一层：风险引擎——判定「是不是 Agent」](#二第一层风险引擎判定是不是-agent)
  - [2.1 规则表与计分（可直接复用）](#21-规则表与计分可直接复用)
  - [2.2 分档与处置策略](#22-分档与处置策略)
  - [2.3 实施要点与避坑](#23-实施要点与避坑)
- [三、第二层：产品签名库——判定「是哪个 Agent」](#三第二层产品签名库判定是哪个-agent)
  - [3.1 签名数据结构](#31-签名数据结构)
  - [3.2 匹配算法与置信度](#32-匹配算法与置信度)
  - [3.3 签名库建设流程](#33-签名库建设流程)
- [四、第三层：行为序列指纹——UA 伪装时的兜底](#四第三层行为序列指纹ua-伪装时的兜底)
- [五、与处置链的集成](#五与处置链的集成)
- [六、验证清单与实测](#六验证清单与实测)
- [七、边界与已知局限](#七边界与已知局限)
- [附录 A 参考实现代码坐标](#附录-a-参考实现代码坐标)
- [附录 B 关键结论及证据索引](#附录-b-关键结论及证据索引)

---

## 一、方案总览：为什么要三层

单一 UA 词表只能回答「是不是自动化客户端」，且 UA 可以随意伪造。实战可用的指纹体系需要三层互补：

| 层 | 回答的问题 | 输入 | 输出 | 典型用途 |
|---|---|---|---|---|
| L1 风险引擎 | 是不是 Agent / 攻击性多强 | UA、请求头、路径、payload、频率 | 分数 + 信号名 + 决策档位 | 处置（观察/挑战/隔离/阻断） |
| L2 产品签名库 | 具体是哪个产品 | UA + 特征请求头 | 产品名/厂商/类型 + 置信度 + 证据链 | 归因标注、告警分诊、审计 |
| L3 行为序列 | UA 伪装时是否仍暴露自动化 | 会话请求历史（路径+时间戳） | automation_like / human_like + 分数 | 无 UA 特征时的兜底信号 |

参考实现把这两层的分工写成明确注释（`agent_fingerprint.py:1-11`）：风险引擎回答 "is this an agent?"，签名库回答 "which agent is it?"——两层独立维护、互不依赖，最终都汇入事件流。三条信号叠加后，攻击者即使伪造 UA，仍会被「缺人类请求头」「匀速请求序列」「蜜罐水印回显」等旁路信号钉住。

## 二、第一层：风险引擎——判定「是不是 Agent」

### 2.1 规则表与计分（可直接复用）

以下两张 UA 词表和配套规则来自参考实现，已按「可疑客户端 / Agent 客户端」两级计分设计，可直接迁移：

**`SUSPICIOUS_UA_MARKERS`（22 条，命中 +30）**——通用脚本与扫描器：curl、wget、python-requests、python-urllib、aiohttp、httpx、go-http-client、okhttp、sqlmap、nikto、nuclei、dirsearch、ffuf、gobuster、wfuzz、zgrab、nmap、masscan、playwright、puppeteer、headlesschrome、browser-use。

**`AGENT_UA_MARKERS`（33 条，命中 +40）**——按四组维护：

| 分组 | 条目 | 维护口径 |
|---|---|---|
| 浏览器自动化（4） | browser-use、playwright、puppeteer、headlesschrome | 与可疑表重叠，取更高分 |
| 通用 Agent/LLM 关键词（8） | chatgpt、claude、gpt-4、llm、ai-agent、langchain、crewai、autogpt | 宽关键词，容忍 UA 变体 |
| 编码 Agent CLI（12） | codex、opencode、gemini、google-genai、kimi、moonshot、cursor、aider、cline、windsurf、codebuddy、junie | 产品名 |
| 渗透测试 Agent 框架（9） | hexstrike、strix、pentagi、pentestagent、pentest-agent、artex、cyberstrikeai、slingshoot、sapper | 你的平台明确想捕获的目标，其自带 UA 直接计入 |

配套请求头规则：

- 特征头（任一出现 +25）：`x-openai` / `x-anthropic` / `x-langfuse` / `x-agent` / `x-automated`；
- **缺人类头启发式**：真实浏览器必带的 `sec-fetch-site`、`sec-fetch-mode`、`sec-fetch-dest`、`accept-language` 缺 ≥2 项 → +15。这是 UA 伪装成 Chrome 时的旁路检测，建议必上；
- payload 正则（路径穿越/SQLi/XSS/命令注入 4 组，每组 +25）：对 URL 解码后的 path+query 匹配，pattern 收紧压误报；
- UA 完全缺失：+20；
- 频率：会话或 IP 近期事件 ≥12 → +20，≥6 → +10（按 IP 聚合是为了防 cookie 轮换）；
- 蜜罐水印回显：+70（见[注入实施方案](prompt-injection.md)第六节，是最强的单一信号）。

### 2.2 分档与处置策略

参考实现的分档（`risk_engine.py:237-246`）建议直接沿用：

| 分数 | 决策 | 处置 |
|---|---|---|
| ≥95 | block | 直接阻断（Agent 信号触发时返回带检测类型的 403 页） |
| ≥70 | isolate | 会话/IP 持久隔离，返回 503 页（页面内可藏归因指令，见注入专题） |
| ≥45 | challenge | 下发 JS 挑战；反复绕过（≥3 次）追加 challenge_evasion +30 逐级升档 |
| ≥20 | observe | 记录不处置 |
| <20 | allow | 放行 |

实施前提要想清楚**在哪里强制执行**：参考实现的蜜罐面对外只记录不处置（`observe_only_all`），处置在管理平面强制——蜜罐里把「敌意访客」挡在门外会破坏欺骗链；而你自己若在真实业务前部署，则相反：蜜饵面不处置，业务面处置。

### 2.3 实施要点与避坑

1. **copilot 一类编辑器补全 UA 要有意排除**：参考实现因外部误报反馈明确把 `copilot` 移出风险词表（`risk_engine.py:53-56` 注释），但产品标签照打。原则：**非自主执行的编辑器流量不计攻击分，自主执行的 CLI/框架才计**。
2. **渗透框架 UA 与上面立场相反、有意计入**（L63-66）：它们是你想捕获的对象，自带 UA 落入即加分。两类立场都要在词表注释里写明理由，避免后人「顺手统一」。
3. 每条规则的分数、条件都集中在一个 `classify_http_request` 函数里（顺序累加、无权重隐藏），便于审计和调参——建议同样做成**单一入口、扁平累加**。

## 三、第二层：产品签名库——判定「是哪个 Agent」

### 3.1 签名数据结构

每条签名五个字段（`agent_fingerprint.py:18-248`）：

| 字段 | 含义 | 置信度贡献 |
|---|---|---|
| `ua_markers` | 强 UA 标记（产品专属串） | 0.90 |
| `ua_weak_markers` | 弱标记（泛子串，可能误报） | 0.60 |
| `ua_prefixes` | UA 前缀 | 0.75 |
| `header_markers` | 特征头名（存在即加分） | max(conf, 0.65) + 0.03 |
| `header_pairs` | 头名+值对 | max(conf, 0.75) + 0.05 |

置信度封顶 0.98。参考实现共 31 条签名（coding_agent 14 / assistant 1 / automation 3 / framework 11 / api_sdk 2），完整清单见[总览笔记附录](source-notes.md#附录-a-代码坐标索引)。几个值得直接抄的特征头：Claude Code 带 `anthropic-client`/`anthropic-beta`/`x-stainless-organization`；Codex 带 `originator: codex` 对 + `openai-beta` 头。

### 3.2 匹配算法与置信度

匹配主函数逻辑（`identify_from_headers`，L267-333），约 60 行可实现：

1. 遍历全部签名；UA/头做小写归一后做子串/前缀/头对匹配；
2. 每个命中的证据逐条记入 `evidence`（如 `ua: codex_cli_rs`、`header: originator=codex`）；
3. 按 §3.1 计分，取**置信度最高的一个**为结果；
4. 输出 `{key, label, vendor, kind, confidence, version, evidence}`。

关键设计：**evidence 逐条可审计**——运维在事件详情里能看到判定为什么成立，这是它与「裸正则打标」的核心区别，也是误报争议时唯一能复盘的东西。

版本提取：对命中标记后的版本号做 `marker[/ v]?(\d+(\.\d+)+…)` 正则提取（截断 32 字符），实测 `codex_cli_rs/0.9.0` → `"0.9.0"`。

### 3.3 签名库建设流程

1. **真流量优先**：参考实现的前 6 个编码 Agent（claude code / codex / opencode / kimi / pi / zcode）是拿真实演练流量验证 UA 的，其余才用产品规范 UA（L8-10 注释）。建议同样：能抓真包就抓真包。
2. **分类维护**：按 kind 分组，新产品进库先定 kind（是编码 Agent、自动化框架还是 SDK），渗透框架类产品注明「捕获目标」。
3. **弱标记只做归因、不进风险词表**：`claude`/`gemini`/`kimi` 这类泛子串放在 L2（误报只影响标签），与 L1 计分词表分开维护（L1 是独立 33 条）。
4. **签名库与 README/文档同步**：参考实现 README 写 23 条、代码实际 31 条（新增 8 个渗透框架未同步文档）——你们的签名库要有版本号或导出计数，避免口径漂移。

## 四、第三层：行为序列指纹——UA 伪装时的兜底

当攻击者把 UA 改成正常浏览器，前两层失效，用会话请求历史兜底。参考实现的算法（`counter_intel.py::classify_behavior`，L138-176）四个信号、扁平累加：

| 信号 | 条件 | 分数 |
|---|---|---|
| no_static_assets | 静态资源占比 <5% 且路径数 ≥4 | +30 |
| high_path_diversity | 去重路径比 >0.9 且路径数 ≥5 | +25 |
| uniform_intervals | 请求间隔变异系数倒数 >0.75（匀速） | +25 |
| sustained_sequenced_requests | 路径数 ≥10 且静态占比 <10% | +20 |

分数 ≥50 判 `automation_like`，≥75 附加 strong 信号；阈值建议做成可配置（参考实现在管理台暴露 min_events / classify_every / auto / strong 四个参数，默认 5/5/50/75）。

触发机制：每 N 次请求（默认第 5 次）对会话最近 11 条事件 + 当前请求做一次分类，结果写进事件 payload 而非实时处置——离线标注为主，避免误判直接拦截真人。

**已知局限（实施时必须补位）**：行为分类按**会话**聚合，无 cookie 客户端每个请求都是新会话、永远凑不够 min_events。无状态工具的兜底要靠 **IP 级聚合的 velocity 信号**（§2.1）——参考实现注释明示这个设计原因（`risk_engine.py:210-218`）。实测验证见第六节。

## 五、与处置链的集成

指纹不是孤立输出，落点有五个（参考实现逐一实现）：

1. **事件归因**：每请求落库时跑 L2，命中写 `payload.agent_fingerprint` + `agent_product:<key>` 信号；攻击者画像按产品聚合打「AI Agent」标签。
2. **处置页携带指纹**：隔离短路响应的记录事件带完整指纹；block 页若由 Agent 信号触发，直接报出检测到的产品类型。
3. **蜜饵内容个性化**：指令文件蜜饵读取事件记录产品 label，为后续定向话术（见注入专题）提供输入。
4. **抬分联动**：L1 的 `ai_agent_ua_detected` / `ai_agent_header_detected` 直接进风险分，与蜜饵命中（+45）、水印回显（+70）叠加后跨过处置档位。
5. **告警分诊**：信号名进告警 payload，值班按 `agent_product` / `behavior_automation` / `prompt_canary_echo` 优先级排序。

## 六、验证清单与实测

上线前建议按下表逐项验证（本机已按此执行，环境：管理面 4877 + 蜜罐面 48777，全新数据库）：

| # | 验证项 | 操作 | 通过标准 | 实测结果 |
|---|---|---|---|---|
| V1 | L2 强特征命中 | `curl -A "codex_cli_rs/0.9.0 (…)" -H "originator: codex" -H "openai-beta: responses=v1"` | 事件 payload 有产品指纹、evidence ≥2 条 | ✓ `key: codex, confidence: 0.98, version: 0.9.0, evidence: [ua, header×2]` |
| V2 | L1 联动抬分 | 同上请求 | `ai_agent_ua_detected`(+40) + `missing_human_headers`(+15) → challenge 档 | ✓ risk 55 |
| V3 | L3 触发节奏 | 同会话（带 cookie）匀速 6 连击 | 第 5 次请求触发分类，写 payload.behavior | ✓ score 50 automation_like（no_static_assets + sustained_sequenced_requests） |
| V4 | copilot 不误报 | 带 copilot UA 访问 | 无风险加分、有产品标签 | 依词表设计（源码核验，未实测） |
| V5 | 无 cookie 客户端 | 不带 cookie 连击 | 无行为分类触发（会话聚合局限） | ✓（V3 失败路径验证） |
| V6 | observe 面不处置 | 蜜罐面高分数请求 | 只记录不 403/不挑战 | ✓ 响应头无决策头 |

## 七、边界与已知局限

1. **UA 可伪造**：L1/L2 都是明文匹配，改一个字符串即可绕过。真正的对抗纵深在旁路信号（缺人类头、匀速序列、水印回显），实施时不要把 UA 词表当主防线。
2. **弱标记误报面**：泛子串只做归因不做处置（§3.3 第 3 条），否则会误伤带关键词的正常工具。
3. **行为指纹对无 cookie 客户端失效**：设计取舍，靠 IP 级 velocity 补位（§四）。
4. **签名库是手工清单**：无热加载/远程下发，新产品需要发版更新——如果你需要快速响应，建议把签名库做成可远程下发的数据文件（参考实现的 sensor 特征表就是这个形态，`features.json`）。
5. **合规前提**：指纹结果用于授权范围内的蜜罐/防御场景；对真实用户的请求头采集注意最小化与留存策略。

## 附录 A 参考实现代码坐标

以下坐标对应 AgentCapture 快照 `728ffa0`，本文各节设计点的核验出处：

| 设计点 | 坐标 |
|---|---|
| 两层分工注释 | app/services/agent_fingerprint.py:1-11 |
| L2 签名库（31 条） | app/services/agent_fingerprint.py:18-248 |
| L2 匹配与置信度 | app/services/agent_fingerprint.py:267-333 |
| L2 版本提取 | app/services/agent_fingerprint.py:253-259 |
| L1 可疑 UA 词表（22） | app/services/risk_engine.py:7-30 |
| L1 Agent UA 词表（33）+ copilot/渗透框架立场注释 | app/services/risk_engine.py:32-76 |
| L1 特征头/缺人类头 | app/services/risk_engine.py:78-86 |
| L1 payload 正则 | app/services/risk_engine.py:98-142 |
| L1 打分主函数与分档 | app/services/risk_engine.py:157-248 |
| L3 行为分类算法 | app/services/counter_intel.py:138-176 |
| L3 触发节奏（每 N 次请求） | app/middleware/injector.py:490-551 |
| 指纹写事件 payload | app/middleware/injector.py:473-479 |
| 隔离短路带指纹 | app/middleware/injector.py:274-281 |
| L3 参数配置默认值 | app/services/surface_config.py:248-253 |
| 蜜饵事件带产品 label | app/routes/counter_offense.py:47-49、111-160 |
| README「23」旧口径（反向教训） | README.md:63、README.md:130 |

## 附录 B 关键结论及证据索引

| # | 结论 | 证据 |
|---|---|---|
| B1 | 三层结构互补：L1 判攻击性、L2 判产品、L3 判自动化行为；独立维护、汇入同一事件流 | agent_fingerprint.py:1-11；risk_engine.py:157-248；counter_intel.py:138-176 |
| B2 | L2 置信度：强 UA 0.9 / 弱 0.6 / 前缀 0.75，特征头 +0.03（底 0.65）、头值对 +0.05（底 0.75），封顶 0.98；evidence 逐条可审计 | agent_fingerprint.py:284-316 |
| B3 | copilot 从风险词表有意排除（误报反馈），渗透框架有意计入（捕获目标）；两种立场均注释明示 | risk_engine.py:53-66 |
| B4 | L1 分档 ≥95 block / ≥70 isolate / ≥45 challenge / ≥20 observe；水印回显 +70 为最高单一信号 | risk_engine.py:237-246、206-208 |
| B5 | 实测 V1/V2：codex_cli_rs UA + 双特征头 → 置信度 0.98、版本 0.9.0、三条证据；风险 55 challenge | 本文第六章实测（events 表 payload_json） |
| B6 | 实测 V3：同会话第 5 次请求触发行为分类，score 50 automation_like | 本文第六章实测（payload_json.behavior） |
| B7 | L3 按会话聚合，无 cookie 客户端不生效；无状态工具依赖 IP 级 velocity | injector.py:509-527；risk_engine.py:210-218（注释） |
| B8 | 文档与签名库数量脱节（README 23 vs 代码 31）是签名库运营的反面教材 | README.md:63；agent_fingerprint.py:18-248 逐条清点 |
