---
title: Markdown Rendering Test
theme: meridian-lite
---

# Hello World

Testing **bold**, *italic*, `inline code`, and [links](https://example.com).

## Code Block

```python
def hello():
    print("works!")

class Renderer:
    def render(self, text: str) -> str:
        return f"<p>{text}</p>"
```

```bash
echo "Shell highlighting too"
curl -s https://api.example.com | jq '.data'
```

## Table

| Feature | Status | Notes |
|---------|--------|-------|
| Tables | OK | GFM-style |
| Code highlighting | OK | Pygments |
| Dark mode | OK | Toggle button |
| Task lists | OK | Checkboxes |

## Task List

- [x] Frontmatter parsing
- [x] Markdown rendering
- [x] Theme templates
- [ ] More themes later

## Blockquote

> This is a blockquote with **bold** and `code` inside.
> It supports multiple lines.

## Card & Callout Blocks

:::card{label="🧩 Stage 2.1 交接 / HANDOFF" color="teal"}
### Stage 2.1 交出來的東西, 在這裡要被升級

上一站結束時, 你手上有的是 **3 個 lens** (Misuse / Misalignment / Societal Disruption) — 這是風險的**分類框架**。但分類完, 一家 frontier lab 不能只靠分類做決定。

- **問題在哪裡**: Dario 手上放一份 Claude capability report
- **本 stage 要做的**: 從第一原理推出 RSP 骨架
- **推導終點**: capability-gated deployment framework

:::callout
🎯 **這一站的 meta-move:** 我們**先不給你看 Anthropic 答案**, 每題都讓你先自己推, 再對照。
:::

:::

:::card{label="💡 INSIGHT" color="green"}
This is a **green** insight card. Supports all markdown inside.
:::

:::card{label="⚠️ WARNING" color="amber"}
This is an **amber** warning card.
:::

## Fold Blocks

:::fold 點擊展開 — :::fold 語法
This content is **hidden by default**.

- Supports all markdown inside
- Tables, code, lists, etc.

```python
print("code inside fold!")
```
:::

:::fold Another fold with no content title override
Just more text here.
:::

---

*End of test.*
