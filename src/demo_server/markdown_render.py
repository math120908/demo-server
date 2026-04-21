"""Server-side Markdown → HTML rendering with theme templates."""

import re
from pathlib import Path

import yaml
from jinja2 import Template
from markdown_it import MarkdownIt
from markdown_it.rules_inline import StateInline
from mdit_py_plugins.container import container_plugin
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name, guess_lexer, TextLexer

_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_FIRST_HEADING_RE = re.compile(r"^#\s+(.+)", re.MULTILINE)
_HEADING_RE = re.compile(r"<(h[23])>(.*?)</\1>", re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_ATTR_RE = re.compile(r'(\w+)="([^"]*)"')

# Predefined color palettes for card/callout blocks
_COLORS = {
    "teal":   {"border": "#06b6d4", "bg": "#ecfeff", "bg2": "#cffafe",
               "dark-bg": "#042f3a", "dark-bg2": "#083344", "dark-border": "#22d3ee",
               "badge-bg": "#06b6d4", "badge-text": "#fff",
               "text": "#0e7490", "dark-text": "#67e8f7"},
    "purple": {"border": "#7c3aed", "bg": "#f5f3ff", "bg2": "#ede9fe",
               "dark-bg": "#2e1065", "dark-bg2": "#1e1b4b", "dark-border": "#a78bfa",
               "badge-bg": "#7c3aed", "badge-text": "#fff",
               "text": "#5b21b6", "dark-text": "#c4b5fd"},
    "amber":  {"border": "#f59e0b", "bg": "#fffbeb", "bg2": "#fef3c7",
               "dark-bg": "#422006", "dark-bg2": "#3a2407", "dark-border": "#fbbf24",
               "badge-bg": "#f59e0b", "badge-text": "#78350f",
               "text": "#92400e", "dark-text": "#fcd34d"},
    "green":  {"border": "#059669", "bg": "#ecfdf5", "bg2": "#d1fae5",
               "dark-bg": "#052e1a", "dark-bg2": "#064e3b", "dark-border": "#34d399",
               "badge-bg": "#059669", "badge-text": "#fff",
               "text": "#065f46", "dark-text": "#a7f3d0"},
    "red":    {"border": "#dc2626", "bg": "#fef2f2", "bg2": "#fee2e2",
               "dark-bg": "#450a0a", "dark-bg2": "#3b0a0a", "dark-border": "#f87171",
               "badge-bg": "#dc2626", "badge-text": "#fff",
               "text": "#991b1b", "dark-text": "#fca5a5"},
    "blue":   {"border": "#2563eb", "bg": "#eff6ff", "bg2": "#dbeafe",
               "dark-bg": "#1e3a5f", "dark-bg2": "#172554", "dark-border": "#60a5fa",
               "badge-bg": "#2563eb", "badge-text": "#fff",
               "text": "#1e40af", "dark-text": "#93c5fd"},
}
_TEMPLATE_CACHE: dict[str, Template] = {}
_THEMES_DIR = Path(__file__).parent / "themes"


def parse_frontmatter(content: str) -> tuple[dict, str]:
    """Extract YAML frontmatter and return (meta, body)."""
    m = _FRONTMATTER_RE.match(content)
    if not m:
        return {}, content
    try:
        meta = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError:
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    return meta, content[m.end():]


def _highlight_code(code: str, lang: str, _attrs: str) -> str:
    """Pygments-based code block highlighting."""
    try:
        lexer = get_lexer_by_name(lang) if lang else guess_lexer(code)
    except Exception:
        lexer = TextLexer()
    return highlight(code, lexer, HtmlFormatter(nowrap=True, cssclass="highlight"))


def _make_checkbox_plugin(md: MarkdownIt) -> None:
    """Minimal task-list plugin: converts [ ] and [x] in list items."""
    def task_list_replace(state: StateInline, silent: bool) -> bool:
        if state.pos + 3 > state.posMax:
            return False
        src = state.src[state.pos:]
        if src.startswith("[ ] "):
            if silent:
                return True
            token = state.push("html_inline", "", 0)
            token.content = '<input type="checkbox" disabled="" /> '
            state.pos += 4
            return True
        if src.startswith("[x] ") or src.startswith("[X] "):
            if silent:
                return True
            token = state.push("html_inline", "", 0)
            token.content = '<input type="checkbox" checked="" disabled="" /> '
            state.pos += 4
            return True
        return False

    md.inline.ruler.after("image", "task_list", task_list_replace)


def _slugify(text: str) -> str:
    """Convert heading text to a URL-friendly slug."""
    text = _TAG_RE.sub("", text).strip()
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    return re.sub(r"[\s]+", "-", text).strip("-").lower()


def _inject_heading_ids(html: str) -> tuple[str, list[dict]]:
    """Add id attributes to h2/h3 tags and extract TOC entries."""
    toc_entries: list[dict] = []
    seen_slugs: dict[str, int] = {}

    def replacer(m: re.Match) -> str:
        tag = m.group(1)
        inner = m.group(2)
        text = _TAG_RE.sub("", inner).strip()
        slug = _slugify(text)
        # Deduplicate slugs
        if slug in seen_slugs:
            seen_slugs[slug] += 1
            slug = f"{slug}-{seen_slugs[slug]}"
        else:
            seen_slugs[slug] = 0
        toc_entries.append({"level": int(tag[1]), "text": text, "id": slug})
        return f'<{tag} id="{slug}">{inner}</{tag}>'

    html = _HEADING_RE.sub(replacer, html)
    return html, toc_entries


def _build_toc_html(entries: list[dict]) -> str:
    """Build TOC HTML from heading entries."""
    if not entries:
        return ""
    lines = ['<nav class="toc" aria-label="Table of contents">',
             '<div class="toc-title">目錄</div>', "<ol>"]
    for entry in entries:
        indent = "  " if entry["level"] == 3 else ""
        cls = ' class="toc-sub"' if entry["level"] == 3 else ""
        lines.append(f'{indent}<li{cls}><a href="#{entry["id"]}">{entry["text"]}</a></li>')
    lines.append("</ol></nav>")
    return "\n".join(lines)


def _parse_attrs(info: str, prefix: str) -> dict[str, str]:
    """Parse {key="value" key2="value2"} attributes from container info string."""
    text = info.strip().removeprefix(prefix).strip()
    # Strip surrounding braces if present
    if text.startswith("{") and "}" in text:
        text = text[1:text.index("}")]
    return dict(_ATTR_RE.findall(text))


def _fold_render(self, tokens, idx, _options, env):
    """Render :::fold blocks as <details><summary>."""
    token = tokens[idx]
    if token.nesting == 1:
        title = token.info.strip().removeprefix("fold").strip() or "Details"
        # Strip {attrs} from title if present
        if "{" in title:
            title = title[:title.index("{")].strip()
        return f'<details class="fold-block"><summary>{title}</summary>\n'
    return "</details>\n"


def _card_render(self, tokens, idx, _options, env):
    """Render :::card blocks as styled section cards."""
    token = tokens[idx]
    if token.nesting == 1:
        attrs = _parse_attrs(token.info, "card")
        color = attrs.get("color", "blue")
        label = attrs.get("label", "")
        palette = _COLORS.get(color, _COLORS["blue"])
        style = (
            f"--card-border:{palette['border']};--card-bg:{palette['bg']};"
            f"--card-bg2:{palette['bg2']};--card-text:{palette['text']};"
            f"--card-dark-bg:{palette['dark-bg']};--card-dark-bg2:{palette['dark-bg2']};"
            f"--card-dark-border:{palette['dark-border']};--card-dark-text:{palette['dark-text']};"
            f"--card-badge-bg:{palette['badge-bg']};--card-badge-text:{palette['badge-text']};"
        )
        label_html = f'<div class="card-label">{label}</div>\n' if label else ""
        return f'<div class="md-card" style="{style}">\n{label_html}'
    return "</div>\n"


def _callout_render(self, tokens, idx, _options, env):
    """Render :::callout blocks as dashed-border callout boxes."""
    token = tokens[idx]
    if token.nesting == 1:
        return '<div class="md-callout">\n'
    return "</div>\n"


def render_markdown(md_text: str, allow_html: bool = False) -> str:
    """Convert markdown text to HTML string."""
    md = MarkdownIt("gfm-like", {"highlight": _highlight_code})
    if allow_html:
        md.options["html"] = True
    _make_checkbox_plugin(md)
    container_plugin(md, name="fold", render=_fold_render)
    container_plugin(
        md, name="card", render=_card_render, marker=":",
        validate=lambda params, *_: params.strip().startswith("card"),
    )
    container_plugin(
        md, name="callout", render=_callout_render, marker=":",
        validate=lambda params, *_: params.strip().startswith("callout"),
    )
    return md.render(md_text)


def get_template(theme_name: str) -> Template:
    """Load a Jinja2 template for the given theme, with caching."""
    if theme_name in _TEMPLATE_CACHE:
        return _TEMPLATE_CACHE[theme_name]
    path = _THEMES_DIR / theme_name / "template.html"
    if not path.is_file():
        path = _THEMES_DIR / "meridian-lite" / "template.html"
        theme_name = "meridian-lite"
    tmpl = Template(path.read_text())
    _TEMPLATE_CACHE[theme_name] = tmpl
    return tmpl


def render_md_file(file_path: Path) -> str:
    """Full pipeline: read file → parse frontmatter → render → template."""
    content = file_path.read_text(encoding="utf-8")
    meta, body = parse_frontmatter(content)

    theme = meta.get("theme", "meridian-lite")
    lang = meta.get("lang", "en")
    allow_html = meta.get("allow_html", False)

    # Title resolution: frontmatter > first heading > filename
    title = meta.get("title")
    if not title:
        m = _FIRST_HEADING_RE.search(body)
        title = m.group(1).strip() if m else file_path.stem.replace("-", " ").title()

    html_body = render_markdown(body, allow_html=allow_html)
    html_body, toc_entries = _inject_heading_ids(html_body)
    toc_html = _build_toc_html(toc_entries) if meta.get("toc", True) else ""
    highlight_css = HtmlFormatter().get_style_defs("pre code")
    template = get_template(theme)

    return template.render(
        title=title,
        content=html_body,
        toc=toc_html,
        highlight_css=highlight_css,
        lang=lang,
    )
