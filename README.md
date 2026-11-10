# Agentic ADR 笔记

Uber ADR（Agentic AI Detection and Response）的源码级研究笔记。非官方文档，数字来自代码阅读与本机实测，不转述 README。

## 内容

| 组件 | 笔记 | 覆盖范围 |
|---|---|---|
| Discovery | [discovery/source-notes.md](discovery/source-notes.md) | 18 类 Kind、37 条 catalog、M1–M7 七个阶段、判定层、Coverage、脱敏、三平台实现、实测、测试覆盖 |

## 版本锚定

| 项 | 值 |
|---|---|
| 源码 | `uber/ADR` 的 `Discovery/` 目录 |
| catalog | `2026.10.12` |
| schema | `1.2` |
| Python | 3.11+，仅标准库 |

## 说明

代码坐标在正文写成 `文件::符号`，在附录写成 `文件:行号`。例如 `judge/findings.py::findings_for` 与 `judge/findings.py:32`。

实测数据来自 macOS 单机，路径中的用户名替换为 `<user>`，主机名替换为 `<host>`。所有输出片段取自同一次运行，未拼接。

笔记里出现的数字都能对回代码常量或实测输出。与官方 README 口径不一致的地方，以代码为准并标注差异。

## 范围

Discovery 已完成。Observability、Detection 尚未开始。

引用请注明出处。
