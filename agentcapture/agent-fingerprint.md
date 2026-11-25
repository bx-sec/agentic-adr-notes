# 蜜罐识别 AI 机器人：学习笔记

> 主题：给蜜罐（故意布置的假目标，用来引攻击者上钩、看清对方是谁）加上一套识别 AI 机器人的能力。本文是学习笔记，按重点整理。所有做法参考了开源项目 AgentCapture（版本 728ffa0，2026-11-12），我在本机跑通并验证过。文末附 Sigma 检测规则，专业同行可直接取用。

## 0. 先补几个背景概念

- **蜜罐**：故意放在那里的假网站、假服务，看起来有漏洞和敏感数据，专门用来引攻击者。真用户碰不到，碰到的都是心怀不轨的。
- **User-Agent（UA）**：程序访问网站时自带的一行说明，内容是「我是什么软件」。浏览器会写 Chrome，curl 会写 curl。这行内容是对方自己填的，可以随便写，所以只能当参考，不能当证据。
- **请求头**：请求里除了 UA 还带的一组附加信息。真实浏览器会自动带好几个（比如语言、来源页面），自己写的脚本经常忘带。
- **会话（cookie）**：网站发给浏览器的一个编号，相当于临时通行证。带着同一编号来的请求，网站认为来自同一个访客。

## 1. 整体思路：回答三个问题

| 问题 | 靠什么回答 | 判断出来干什么 |
|---|---|---|
| 来的是不是机器人 | UA、请求头 | 决定要不要拦 |
| 是哪一款机器人 | 对照产品特征清单 | 在记录里标明它是谁，方便后续分析 |
| 它伪装成真人了怎么办 | 看一连串请求的行为 | 兜底：动作很难长期伪装 |

思路：前两步看对方「说了什么」（自我介绍可以撒谎），第三步看对方「怎么做事」（动作很难伪装）。三步互补。

## 2. 看 UA：两张名字清单

准备两张清单，UA 里见到名字就加分。

**清单 A：可疑客户端，22 个名字，见一个加 30 分。** 内容是常见的脚本和扫描工具：curl、wget、python-requests、nmap、sqlmap、nikto、nuclei 等。见到只能说明来的是程序，不一定有 AI 参与。

**清单 B：AI 机器人客户端，33 个名字，见一个加 40 分。** 分四组：

| 组 | 名字 |
|---|---|
| 浏览器自动化（4） | browser-use、playwright、puppeteer、headlesschrome |
| AI 关键词（8） | chatgpt、claude、gpt-4、llm、ai-agent、langchain、crewai、autogpt |
| 编程机器人（12） | codex、opencode、gemini、google-genai、kimi、moonshot、cursor、aider、cline、windsurf、codebuddy、junie |
| 攻击型 AI 框架（9） | hexstrike、strix、pentagi、pentestagent、pentest-agent、artex、cyberstrikeai、slingshoot、sapper |

两条维护经验：

1. Copilot 不放进清单 B。Copilot 是编辑器补全工具，程序员写代码时它也发请求，属于正常工作流量。参考实现最初放进去了，收到误报反馈后移出。原则：不自己执行动作的工具不加攻击分，会自己执行命令的才加。
2. 攻击型框架要放进清单 B。它们就是想抓的目标，自己报上名正好。这条和上一条立场相反，各写注释说明理由，避免后人误改。

另有两条简单规则：UA 一栏完全为空加 20 分；访问了蜜罐故意露出来的假文件路径加 45 分。真用户不会去点这些文件。

## 3. 看请求头：不看 UA 也能抓的三招

1. **缺真人头**。浏览器每次访问都会自动带 `sec-fetch-site`、`sec-fetch-mode`、`sec-fetch-dest`、`accept-language` 这类头。数一数缺几个，缺 2 个以上加 15 分。专治把 UA 伪装成 Chrome 的脚本。
2. **带 AI 身份牌**。`x-openai`、`x-anthropic`、`x-agent`、`x-automated` 这类自定义头是不少 AI 工具自己加的。见到任何一个加 25 分。
3. **请求里有攻击痕迹**。URL 解码后检查 4 类模式（路径穿越、SQL 注入、XSS、命令注入），每命中一类加 25 分。模式写紧一点，压误报。

## 4. 看行为：UA 伪装了也不怕

真人浏览网站：加载图片和样式、来回点同一个页面、快慢不一。机器人：只抓页面不抓图、每个路径只走一次、请求间隔几乎一样。参考实现总结 4 个体征，每条加分：

| 体征 | 判断标准 | 加分 |
|---|---|---|
| 不抓静态资源 | 图片样式占比不到 5%，且路径数不少于 4 | +30 |
| 路径花样多 | 去重后路径占比超过 90%，且路径数不少于 5 | +25 |
| 节奏太均匀 | 请求间隔的波动很小 | +25 |
| 持续扫描 | 请求超过 10 个且仍不抓图 | +20 |

总分 50 以上判定「像机器人」，75 以上判定「很像」。判定结果先写进记录，不直接拦人。

注意一个局限：这套分析按会话统计，靠的是同一张通行证攒够次数。机器人不带 cookie 时，每次都算新面孔，凑不够样本，这套分析不会触发。补位方案：按 IP 统计访问频率（IP 级也统计最近事件数，6 次以上加 10 分，12 次以上加 20 分）。

## 5. 分数怎么用：分档处置

| 分数 | 动作 |
|---|---|
| 95 以上 | 拦截，返回 403 |
| 70 以上 | 隔离 1 小时，返回一张「网站维护中」的假页面 |
| 45 以上 | 弹一道浏览器才能通过的检查（机器人过不了，过不了的次数也记分） |
| 20 以上 | 只记录，不动手 |
| 20 以下 | 放行 |

部署前先想清楚处置装在哪。参考实现分两个门面：蜜罐门面只记录不拦截（蜜罐靠「不拦」才能看清对方），真业务门面才拦截。

另有一条最强规则单独记：蜜罐在网页里藏过一个带编号的字条（见注入笔记），对方的请求里如果原样带回了这个编号，直接加 70 分并拉黑 1 小时。只有把假指令读进去并照做的机器人，才做得到这件事。

## 6. 验证记录

本机实测环境：蜜罐运行在本机两个端口，全新数据库。以下均为真实结果。

| 验证项 | 操作 | 结果 |
|---|---|---|
| 认出具体产品 | 用 Codex 的真实请求头访问：UA 写 codex_cli_rs/0.9.0，另带 originator: codex 和 openai-beta 两个头 | 记录出现产品名 Codex、版本 0.9.0、置信度 0.98，以及三条判定依据（UA 一条、请求头两条） |
| 加分联动 | 同上 | UA 加 40 分，缺真人头加 15 分，合计 55 分，进入「检查」档 |
| 行为分析 | 同一会话（带 cookie）每秒访问一个假数据页面，连访 6 次 | 第 5 次请求触发判定，得 50 分（不抓图加 30，持续扫描加 20），标记为像机器人 |
| 行为分析对无 cookie 客户端 | 不带 cookie 连访 | 不触发，符合已知局限 |
| 证据可查 | 查看事件记录 | 判定依据逐条可见，可审计 |

置信度打分公式（识别产品时用）：UA 强特征命中 0.9，弱特征 0.6，前缀 0.75；特征头存在再加一点（0.03），头名和值都对上再加一点（0.05），最高封顶 0.98。版本号从 UA 里顺带提取。判定证据逐条列出，出了误报有据可查，这是它和普通正则打标的主要区别。

## 7. Sigma 检测规则

把上面的识别方法整理成了 7 条 Sigma 规则，放在 [sigma/](sigma/) 目录，主流 SIEM（Splunk、Elastic、Loki、Wazuh 等）可直接导入。Sigma 是通用日志检测规则的 YAML 格式，规则里写「在什么日志里、匹配什么条件」，后端负责翻译成各平台的查询语句。

| 规则文件 | 抓什么 | 级别 |
|---|---|---|
| [agentcapture_ai_agent_cli_ua.yml](sigma/agentcapture_ai_agent_cli_ua.yml) | 编程机器人 UA（Codex、Claude Code、Cursor 等强特征） | medium |
| [agentcapture_ai_agent_weak_ua_keywords.yml](sigma/agentcapture_ai_agent_weak_ua_keywords.yml) | 宽泛 AI 关键词，用于标注和狩猎，不建议直接告警 | low |
| [agentcapture_ai_automation_pentest_framework_ua.yml](sigma/agentcapture_ai_automation_pentest_framework_ua.yml) | 浏览器自动化和攻击型 AI 框架 UA | high |
| [agentcapture_ai_agent_custom_headers.yml](sigma/agentcapture_ai_agent_custom_headers.yml) | AI 工具自带的身份牌头（x-openai、x-agent 等） | medium |
| [agentcapture_missing_browser_fetch_metadata.yml](sigma/agentcapture_missing_browser_fetch_metadata.yml) | 伪装浏览器但忘带真人头的请求 | medium |
| [agentcapture_agent_canary_echo.yml](sigma/agentcapture_agent_canary_echo.yml) | 蜜罐字条记号被原样带回（配合注入笔记使用） | critical |
| [agentcapture_bait_route_with_agent_ua.yml](sigma/agentcapture_bait_route_with_agent_ua.yml) | 蜜饵路径访问 + AI 机器人 UA，两个强信号叠加 | high |

使用前注意三点：

1. 字段名要按自家日志管道调整。规则里用的是 IIS 风格的 `cs(User-Agent)`、`c-uri`，nginx 日志对应 `http_user_agent`、`uri`，ECS 对应 `http.request.headers.*`、`url.original`。
2. 「缺真人头」这条规则先确认日志管道保留了 sec-fetch 和 accept-language 头。很多采集端默认只留 UA，头被裁掉时这条规则会全部误报。
3. 严重级别是按参考实现的打分给的：UA 类规则只能说明「来的是机器人」，记号回显（critical）才是实锤，两者处置等级不同。

其中一条的原文，感受一下格式：

```yaml
title: AI Coding Agent CLI User-Agent
id: e5117698-ac79-4206-a924-cd1360719be7
status: experimental
logsource:
    category: webserver
detection:
    selection:
        cs(User-Agent)|contains:
            - 'codex_cli_rs'
            - 'claude-cli'
            - 'opencode'
            - 'cursor'
            - 'aider'
            - 'cline'
            - 'windsurf'
    condition: selection
falsepositives:
    - Authorized security assessments using these CLIs
level: medium
```

## 8. 注意事项

1. UA 随便改，前两步都可绕过。体系里真正难绕的是缺真人头、行为分析、字条记号回显这三条旁路证据。
2. 宽泛关键词（claude、gemini 这类）只用于标注，不用于拦人，否则误伤。
3. 行为分析对不带 cookie 的客户端无效，记得配 IP 频率兜底。
4. 产品清单要人维护、做版本管理。参考实现文档写 23 种、代码实际 31 种，文档没跟上，引以为戒。
5. 置信度打分要有封顶（0.98），证据要能逐条展示。

