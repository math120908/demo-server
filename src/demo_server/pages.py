"""Standalone HTML pages: passcode, welcome listing, and move-redirect."""

from __future__ import annotations

import html
import json
from pathlib import Path

PASSCODE_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Passcode required &mdash; %%MODULE%%</title>
<style>
  :root { --bg:#f0f2f5; --card:#fff; --fg:#1a1a2e; --muted:#6b7280;
    --accent:#0a66c2; --accent-hover:#004182; --border:#e2e8f0; --danger:#dc2626; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0a101e; --card:#111827; --fg:#e2e8f0; --muted:#94a3b8;
      --accent:#58a6ff; --accent-hover:#79b8ff; --border:#1e293b; --danger:#f87171; }
  }
  * { box-sizing:border-box; }
  body { margin:0; min-height:100vh; min-height:100dvh; display:flex;
    align-items:center; justify-content:center; padding:1.5rem;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans TC",sans-serif;
    background:var(--bg); color:var(--fg); }
  .card { background:var(--card); border:1px solid var(--border); border-radius:16px;
    box-shadow:0 8px 30px rgba(0,0,0,.10); padding:2.2rem 1.9rem; width:100%;
    max-width:380px; }
  .lock { font-size:2rem; line-height:1; text-align:center; }
  h1 { font-size:1.25rem; margin:.7rem 0 .2rem; text-align:center; word-break:break-word; }
  .sub { color:var(--muted); font-size:.88rem; text-align:center; margin:0 0 1.4rem; }
  label { display:block; font-size:.8rem; font-weight:600; color:var(--muted);
    letter-spacing:.04em; text-transform:uppercase; margin-bottom:.35rem; }
  input[type=password] { width:100%; font-size:16px; padding:.7rem .85rem;
    border:1px solid var(--border); border-radius:9px; background:var(--bg);
    color:var(--fg); }
  input[type=password]:focus { outline:2px solid var(--accent); outline-offset:1px;
    border-color:var(--accent); }
  .err { color:var(--danger); font-size:.85rem; margin:.6rem 0 0; min-height:1.2em; }
  button { width:100%; margin-top:1.1rem; padding:.72rem 1rem; font-size:1rem;
    font-weight:600; color:#fff; background:var(--accent); border:none;
    border-radius:9px; cursor:pointer; transition:background .15s; }
  button:hover { background:var(--accent-hover); }
  @media (min-width:421px) { .card { padding:2.4rem 2.1rem; } }
</style>
</head>
<body>
  <main class="card">
    <div class="lock" aria-hidden="true">&#128274;</div>
    <h1>%%MODULE%%</h1>
    <p class="sub">This module is protected.</p>
    <form method="post" action="/%%MODULE_ATTR%%/__auth__">
      <label for="passcode">Passcode</label>
      <input id="passcode" type="password" name="passcode"
             autocomplete="current-password" autofocus required />
      <input type="hidden" name="next" value="%%NEXT%%" />
      <p class="err" role="alert" aria-live="polite">%%ERROR%%</p>
      <button type="submit">Unlock</button>
    </form>
  </main>
</body>
</html>
"""

WELCOME_PAGE = """\
<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>demo-server</title>
<style>
  :root {{ --ink: #1f2430; --muted: #8a93a3; --line: #eceef2;
    --star: #f59e0b; --bg: #f0f2f5; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    min-height: 100vh; background: var(--bg); color: var(--ink);
    display: flex; justify-content: center; padding: 3rem 1rem; }}
  .panel {{ background: #fff; border: 1px solid var(--line); border-radius: 14px;
    box-shadow: 0 4px 24px rgba(20,30,60,.06); max-width: 600px; width: 100%;
    height: fit-content; padding: 1.6rem 1.7rem; }}
  .title {{ font-size: 1.5rem; font-weight: 750; }}
  .tagline {{ font-size: 0.85rem; color: var(--muted); margin: 0.15rem 0 0.3rem; }}
  .sec-label {{ font-size: 0.7rem; font-weight: 700; letter-spacing: 0.09em;
    text-transform: uppercase; color: var(--muted); margin: 1.3rem 0 0.45rem;
    display: flex; align-items: center; gap: 0.5rem; }}
  .sec-label .count {{ background: #f0f2f5; color: var(--muted); border-radius: 20px;
    padding: 0.05rem 0.5rem; font-size: 0.65rem; font-weight: 700; }}
  .row {{ display: flex; align-items: center; justify-content: space-between;
    padding: 0.58rem 0.65rem; border-radius: 9px; text-decoration: none;
    color: var(--ink); transition: background 0.12s; }}
  .row:hover {{ background: #f5f7fb; }}
  .row + .row {{ border-top: 1px solid var(--line); }}
  .name {{ font-size: 0.92rem; font-weight: 520; }}
  .when {{ font-size: 0.75rem; color: var(--muted); white-space: nowrap;
    font-variant-numeric: tabular-nums; }}
  .pin .name::before {{ content: "\\2605"; color: var(--star);
    font-size: 0.8rem; margin-right: 0.4rem; }}
  .fresh .when {{ color: #16a34a; font-weight: 600; }}
</style></head>
<body><div class="panel">
  <div class="title">demo-server</div>
  <div class="tagline">{count} modules</div>
  {modules}
</div></body></html>
"""

REDIRECT_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Page moved — %%SLUG%%</title>
<meta http-equiv="refresh" content="%%SECONDS%%;url=%%TARGET_ATTR%%">
<style>
  :root { --bg:#f0f2f5; --card:#fff; --fg:#1a1a2e; --muted:#6b7280; --accent:#2563eb; --cat:#1a1a2e; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#16161f; --card:#1f1f2b; --fg:#e8e8ea; --muted:#9ca3af; --accent:#60a5fa; --cat:#e8e8ea; }
  }
  * { box-sizing:border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans TC",sans-serif;
    background:var(--bg); color:var(--fg); padding:1.5rem; }
  .card { background:var(--card); border-radius:16px; box-shadow:0 8px 30px rgba(0,0,0,.12);
    padding:2.6rem 2.2rem; max-width:440px; width:100%; text-align:center; }
  .cat { width:120px; height:120px; color:var(--cat); margin:0 auto .6rem; }
  .cat svg { width:100%; height:100%; display:block; }
  h1 { font-size:1.45rem; margin:.3rem 0 .7rem; }
  .desc { color:var(--muted); font-size:.98rem; margin:0 0 1.3rem; }
  .slug { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; background:rgba(127,127,127,.14);
    padding:.12rem .45rem; border-radius:5px; font-size:.92em; }
  .count { font-size:.95rem; color:var(--muted); margin:1.3rem 0 1.1rem; }
  .count b { color:var(--accent); font-size:1.15rem; }
  .btn { display:inline-block; background:var(--accent); color:#fff; text-decoration:none;
    padding:.65rem 1.6rem; border-radius:9px; font-weight:600; font-size:1rem;
    transition:opacity .15s, transform .15s; }
  .btn:hover { opacity:.9; transform:translateY(-1px); }
  .url { margin-top:1.1rem; font-size:.8rem; }
  .url a { color:var(--muted); word-break:break-all; }
</style>
</head>
<body>
  <div class="card">
    <div class="cat">%%CAT%%</div>
    <h1>This page has moved 🐾</h1>
    <p class="desc">%%DESC%%</p>
    <p><span class="slug">/%%SLUG%%</span> has a new home.</p>
    <p class="count">Redirecting in <b id="n">%%SECONDS%%</b> seconds…</p>
    <a class="btn" href="%%TARGET_ATTR%%">Go now →</a>
    <p class="url"><a href="%%TARGET_ATTR%%">%%TARGET_ATTR%%</a></p>
  </div>
  <script>
    var n = %%SECONDS%%;
    var el = document.getElementById("n");
    var timer = setInterval(function () {
      n -= 1;
      if (n <= 0) { n = 0; clearInterval(timer); }
      if (el) { el.textContent = n; }
    }, 1000);
    setTimeout(function () { window.location.href = %%TARGET_JS%%; }, %%SECONDS%% * 1000);
  </script>
</body>
</html>
"""

ASSETS_DIR = Path(__file__).resolve().parent / "assets"
_redirect_cat_cache: str | None = None


def render_passcode_page(module: str, next_url: str, error: str = "") -> str:
    """Render the passcode form for ``module``, preserving ``next_url``."""
    return (
        PASSCODE_PAGE
        .replace("%%MODULE_ATTR%%", html.escape(module, quote=True))
        .replace("%%MODULE%%", html.escape(module))
        .replace("%%NEXT%%", html.escape(next_url or "", quote=True))
        .replace("%%ERROR%%", html.escape(error))
    )


def render_welcome_page(count: int, modules_html: str) -> str:
    """Render the /all/ listing page."""
    return WELCOME_PAGE.format(count=count, modules=modules_html)


def _redirect_cat_svg() -> str:
    global _redirect_cat_cache
    if _redirect_cat_cache is None:
        try:
            _redirect_cat_cache = (ASSETS_DIR / "redirect-cat.svg").read_text()
        except OSError:
            _redirect_cat_cache = ""
    return _redirect_cat_cache


def render_redirect(
    slug: str, target: str, description: str, seconds: int | str = 5
) -> str:
    try:
        seconds = max(0, int(seconds))
    except (TypeError, ValueError):
        seconds = 5
    return (
        REDIRECT_PAGE
        .replace("%%CAT%%", _redirect_cat_svg())
        .replace("%%SECONDS%%", str(seconds))
        .replace("%%SLUG%%", html.escape(slug))
        .replace("%%DESC%%", html.escape(description or ""))
        .replace("%%TARGET_ATTR%%", html.escape(target, quote=True))
        .replace("%%TARGET_JS%%", json.dumps(target))
    )
