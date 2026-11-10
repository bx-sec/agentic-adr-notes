# 协作规范

本仓库的改动规则。条目按序编号，后续新增规则追加在末尾，不复用已废弃的编号。

## 1. 禁止直接提交主分支

`main` 是只读分支。

- 不允许向 `main` 直接 `git push`，也不允许在本地 `main` 上提交后推送。
- 任何新增、修改、删除内容的改动，都必须先建分支，再以 Pull Request 合入。
- 服务端已开启分支保护，直接推送会被 GitHub 拒绝。本地有 pre-commit 钩子提前拦截。
- 没有例外通道。确需绕过，只能由管理员临时关闭保护，事后立即恢复。

## 2. 分支命名

格式 `<type>/<简短描述>`。描述用小写英文、短横线连接，不超过 5 个词。

| 前缀 | 用途 | 例 |
|---|---|---|
| `docs/` | 笔记正文、README、规范 | `docs/detection-source-notes` |
| `fix/` | 修正事实错误、失效链接、错别字 | `fix/catalog-version-anchor` |
| `chore/` | 仓库配置、模板、工具链 | `chore/repo-conventions` |
| `feat/` | 新增结构性能力（脚本、索引、站点） | `feat/notes-index` |

一个分支只做一件事。合入后删除源分支。

## 3. 提交信息

沿用仓库已有的 Conventional Commits 风格：`<type>: <一句话说明>`。

- type 与分支前缀一致：`docs`、`fix`、`chore`、`feat`。
- 说明写"做了什么"，不写"更新文件"这类空话。
- 正文可选。涉及数字、代码坐标、实测结果的改动，正文里写明出处。

```
docs: add ADR Discovery source notes
fix: correct judge gate description against findings.py:32
```

## 4. Pull Request

- 标题与提交信息同格式。
- 描述按 `.github/pull_request_template.md` 填写：改了什么、依据是什么、动了哪些章节。
- 合并用 squash merge，保持 `main` 线性历史。
- 合入后删除源分支。

## 5. 本地流程

```bash
git switch main && git pull
git switch -c docs/your-topic
# 编辑
git add -A && git commit -m "docs: ..."
git push -u origin docs/your-topic
gh pr create --fill
```

仓库自带 `.githooks/pre-commit`，在 `main` 上提交会被拦下。首次克隆后执行一次：

```bash
git config core.hooksPath .githooks
```

钩子只在本地生效，属于提醒层；真正的强制在 GitHub 分支保护。

## 6. 内容约定

引用格式、实测数据标注、版本锚定更新规则见 [README.md](README.md) 的「版本锚定」「说明」两节。改动笔记正文时同步检查这两节是否需要更新。
