# Markdown Rendering — Syntax Guide

demo-server renders `.md` files as styled HTML pages with theme templates. Drop an `index.md` into any DemoDocs module folder and it just works.

## Frontmatter

YAML frontmatter at the top of the file controls rendering options:

```yaml
---
title: Page Title
theme: meridian-lite    # meridian-lite | github | minimal (default: meridian-lite)
lang: en                # HTML lang attribute (default: en)
toc: true               # Show table of contents sidebar (default: true)
allow_html: true        # Allow raw HTML in markdown (default: false)
---
```

**Title resolution priority**: frontmatter `title` → first `# heading` → filename stem.

## Themes

| Theme | Description |
|-------|-------------|
| `meridian-lite` | Outfit/DM Sans/JetBrains Mono fonts, dark mode toggle, TOC sidebar, Meridian color system |
| `github` | GitHub-flavored style, system fonts, white background, clean tables |
| `minimal` | Typography-focused, narrow container (680px), generous line-height, no frills |

Unknown theme names fall back to `meridian-lite`.

## Supported Markdown Features

Standard GFM (GitHub Flavored Markdown):

- **Bold**, *italic*, ~~strikethrough~~, `inline code`
- Links, images
- Ordered and unordered lists
- Blockquotes
- Horizontal rules (`---`)
- GFM tables
- Fenced code blocks with syntax highlighting (Pygments)
- Task lists (`- [x]` / `- [ ]`)

## Fold Blocks

Collapsible sections using `:::fold` syntax:

```markdown
:::fold Click to expand
Hidden content here. Supports **all markdown** inside:

- Lists
- Tables
- Code blocks

:::
```

The text after `:::fold` becomes the summary label. If omitted, defaults to "Details".

```markdown
:::fold
This fold has the default "Details" label.
:::
```

Multiple fold blocks can be nested in sequence (not inside each other).

### Raw HTML Alternative

With `allow_html: true` in frontmatter, you can also write raw `<details>`:

```html
<details>
<summary>Custom HTML fold</summary>

Content here (markdown still renders inside).

</details>
```

## Card Blocks

Styled section containers with gradient backgrounds, colored borders, and floating label badges. Useful for callout sections, handoff notes, insights, warnings, etc.

```markdown
:::card{label="🧩 HANDOFF" color="teal"}
### Section Title

Content with **markdown** support.

- Lists work
- Tables work
- Everything works

:::callout
Nested callout box with dashed border.
:::

:::
```

### Attributes

| Attribute | Description | Default |
|-----------|-------------|---------|
| `label` | Floating badge text at top-left | *(none — no badge shown)* |
| `color` | Color palette name | `blue` |

### Available Colors

| Color | Use case |
|-------|----------|
| `teal` | Handoff, prerequisite, context |
| `purple` | Deep dive, philosophy, open questions |
| `amber` | Warning, caution, red flags |
| `green` | Insight, success, confirmation |
| `red` | Danger, critical, breaking change |
| `blue` | Default, general info, neutral |

### Callout Blocks

Dashed-border inset boxes for emphasis within cards (or standalone):

```markdown
:::callout
Important note with **bold** emphasis.
:::
```

When nested inside a `:::card`, the callout inherits the card's color for its border and bold text.

### Nesting

Cards can contain callouts. The parser matches containers by name, so `:::` closing markers pair correctly:

```markdown
:::card{color="green"}
Outer card content.

:::callout
Inner callout.
:::

More card content.
:::
```

## Code Blocks

Fenced code blocks get Pygments syntax highlighting. Specify the language after the opening fence:

````markdown
```python
def hello():
    print("world")
```

```sql
SELECT * FROM users WHERE active = true;
```

```bash
curl -s https://api.example.com | jq '.data'
```
````

Supported languages: all Pygments lexers (python, bash, sql, javascript, go, rust, java, etc.).

## Table of Contents

Enabled by default (`toc: true`). The TOC is auto-generated from `##` (h2) and `###` (h3) headings:

- h2 → top-level TOC entry
- h3 → indented sub-entry

In `meridian-lite`, the TOC renders as a fixed sidebar (hidden on screens < 1280px) with scroll-spy highlighting. Other themes receive the TOC markup but don't display it by default.

Disable with `toc: false` in frontmatter.

## Index Resolution

When visiting a directory URL (e.g., `/my-module/`):

1. `index.html` → served as static file (takes precedence)
2. `index.md` → rendered through markdown pipeline
3. Neither → 404

Existing `.html` pages are never affected.

## Passcode Protection

Passcode protection (`.encrypt` file) works identically for `.md` and `.html` modules. No special configuration needed.
