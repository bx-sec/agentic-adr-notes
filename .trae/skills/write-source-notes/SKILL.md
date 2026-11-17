---
name: write-source-notes
description: 在本仓库撰写或修订 Uber ADR 组件的源码级研究笔记。Use when the user asks to 写笔记、新建 source-notes、修订某个组件笔记、更新版本锚定或补充实测. Do not use for 与笔记正文无关的仓库配置改动.
---

# 写源码研究笔记

本仓库收录 Uber ADR 各组件（Discovery、Sensor、Detection……）的源码级研究笔记。动笔前先读 [README.md](../../../README.md) 的「版本锚定」「说明」两节与 [CONTRIBUTING.md](../../../CONTRIBUTING.md) 第 6 条「内容约定」，笔记必须遵守这些规则。

## 流程

1. 建分支 `docs/<topic>`，走 PR + squash merge，`main` 只读（见 CONTRIBUTING.md 第 1、2、5 条）。
2. 新组件笔记：按 [references/note-structure.md](references/note-structure.md) 的骨架创建 `<组件>/source-notes.md`。
3. 修订现有笔记：只改涉及的小节，保持原有版式、层级、编号不变。
4. 收尾：检查 README 的「内容」表、「版本锚定」、「说明」三节是否需要同步更新；提交信息用 Conventional Commits，涉及数字、坐标、实测结果的改动在正文写明出处。

## 硬性规则

- **版本锚定**：笔记开头用 blockquote 写明源码快照 commit 与日期、catalog/schema 版本、语言运行时、许可证。
- **代码坐标**：正文写成 `文件::符号`，附录 A 表格写成 `文件:行号`。每个关键技术结论都必须能回溯到代码坐标或明确的外部证据（README / 论文 / commit message），并注明证据来源。
- **数字可溯**：正文出现的每一个数字都要对回代码常量或实测输出。与官方 README 口径不一致时，以代码为准并显式标注差异。
- **实测数据**：标注为 macOS 本机实测；路径中的用户名替换为 `<user>`，主机名替换为 `<host>`；所有输出片段取自同一次运行，禁止拼接。
- **克制表述**：区分「代码证实」「README 声称」「论文描述」「合理推测」四种口径。不要把 assistant 内容等同于完整推理；不同来源对 thinking、工具结果、截断的记录程度不同，需如实说明。
- **配图**：概览图放 `<组件>/assets/`，图注注明「图中流程与数字仅作速查，以正文为准」。正文是唯一口径，图与正文冲突时改图。仓库只有位图而无图源文件时，先说明改图方案（如重写 HTML/SVG 再导出）再动手。

## 结构要点

完整骨架见 [references/note-structure.md](references/note-structure.md)。要点：

- 开头：H1 标题 → 版本锚定 blockquote → 概览图 → 目录（锚点链接）。
- 章节编号用「一、二、三」+ 小节 `1.1`、`1.2`；目录与标题一一对应。
- 章节顺序：是什么（动机/定位/边界）→ 能力范围（能做/不能做）→ 技术实现 → 细节分节（按平台或模块）→ 测试方法 → 安全分析与权衡。
- 附录 A 代码坐标索引（表格）、附录 B 关键技术结论及证据索引（C1..Cn 编号 + 证据来源）、附录 C 术语表。
- 正文以表格和短段落为主，不复述官方 README 能从原文直接读到的内容；重点是读码后才能得出的口径、差异与边界。
