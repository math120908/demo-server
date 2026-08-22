"""Tests for code-block rendering: lexer selection and Pygments CSS sanitizing."""

from __future__ import annotations

from pygments.formatters import HtmlFormatter

from demo_server.markdown_render import (
    _highlight_code,
    _sanitize_pygments_css,
    render_markdown,
)

# A box-drawing ASCII diagram in a bare fence. guess_lexer() used to pick some
# language for this and flag every line-drawing character as an Error token,
# which Pygments paints with a red border.
DIAGRAM = (
    "Claude Code                          Copilot CLI\n"
    "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
    "\u251c\u2500\u2500 permissions.allow  \u2500\u2500\u2500\u2500\u2500\u25ba    (not needed)\n"
    "\u2502   \u2514\u2500\u2500 other cmds\n"
)


def test_unlabelled_fence_is_not_guessed():
    """A bare fence renders as plain text, never as mis-guessed source."""
    out = _highlight_code(DIAGRAM, "", "")
    assert 'class="err"' not in out
    # The diagram survives intact.
    assert "\u251c\u2500\u2500 permissions.allow" in out


def test_labelled_fence_still_highlights():
    out = _highlight_code("def f():\n    return 1\n", "python", "")
    assert 'class="k"' in out  # `def` tokenized as a keyword


def test_unknown_language_falls_back_to_plain_text():
    out = _highlight_code("whatever\n", "no-such-language", "")
    assert 'class="err"' not in out
    assert "whatever" in out


def test_diagram_through_full_markdown_pipeline():
    """End to end: a bare fence in Markdown produces no Error tokens."""
    html = render_markdown("```\n" + DIAGRAM + "```\n")
    assert 'class="err"' not in html


def test_sanitizer_drops_block_background():
    """Pygments' light `pre code` background must not override dark themes."""
    css = _sanitize_pygments_css(HtmlFormatter().get_style_defs("pre code"))
    assert "pre code { background:" not in css


def test_sanitizer_drops_error_border():
    """The red Error-token border reads as a broken page; drop it."""
    css = _sanitize_pygments_css(HtmlFormatter().get_style_defs("pre code"))
    assert "#F00" not in css
    assert "pre code .err { }" in css


def test_sanitizer_keeps_token_colors():
    css = _sanitize_pygments_css(HtmlFormatter().get_style_defs("pre code"))
    token_rules = [ln for ln in css.split("\n") if ln.startswith("pre code .")]
    assert len(token_rules) > 30
