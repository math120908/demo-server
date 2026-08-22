# Reader Enhancements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add login-redirect preservation, a responsive passcode page, and a right-side reader rail (skins, comments, source toggle) to demo-server.

**Architecture:** Four workstreams with **zero file overlap**, so they run in parallel. Workstream A owns all Python; B owns all CSS and the three Jinja templates; C owns `static/reader.js` (rail shell, settings, source toggle); D owns `static/comments.js`. B, C and D communicate only through the DOM/JS contracts frozen in the "Shared Contracts" section below — nobody may change a contract unilaterally.

**Tech Stack:** Python 3.9-compatible FastAPI + Jinja2 + pytest/`fastapi.testclient`; vanilla browser JS (no build step, no framework); Node's built-in `node --test` for the pure comment-anchoring functions.

**Spec:** `docs/superpowers/specs/2026-08-22-reader-enhancements-design.md`

---

## Python 3.9 Constraint (applies to Workstream A only)

Read `CLAUDE.md` before writing Python. Summary: `from __future__ import annotations` at the
top of every module; no `match`/`case`; use `typing.Optional[T]` for anything evaluated at
runtime (FastAPI parameter defaults, `isinstance`, `cast`). `list[...]`/`dict[...]` in
annotations are fine.

---

## File Structure

| File | Owner | Responsibility |
|---|---|---|
| `src/demo_server/pages.py` | A (create) | All non-Markdown HTML pages: passcode, welcome, redirect |
| `src/demo_server/server.py` | A (modify) | Routing, auth, `safe_next`, `/__reader__/` route, `?raw=1` |
| `src/demo_server/markdown_render.py` | A (modify) | Pass `reader_version` to templates |
| `src/demo_server/static_files.py` | A (create) | Reader asset allowlist + version helper |
| `pyproject.toml` | A (modify) | Package-data for `static/` and `assets/` |
| `tests/conftest.py`, `tests/__init__.py` | A (create) | Fixtures |
| `tests/test_auth_next.py` | A (create) | `safe_next` unit tests + login flow integration tests |
| `tests/test_raw_and_assets.py` | A (create) | `?raw=1` and `/__reader__/` route tests |
| `src/demo_server/static/reader.css` | B (create) | Variable contract, 5 ported skins, rail/panel/comment/source CSS |
| `src/demo_server/themes/meridian-lite/template.html` | B (modify) | Rail markup, asset links, bootstrap |
| `src/demo_server/themes/github/template.html` | B (modify) | Variabilize + dark face + rail markup |
| `src/demo_server/themes/minimal/template.html` | B (modify) | Variabilize + dark face + rail markup |
| `src/demo_server/static/reader.js` | C (create) | `window.MdrRail`, settings panel, theme toggle, source toggle |
| `src/demo_server/static/comments.js` | D (create) | Comment anchoring, highlighting, panel, To-tab |
| `tests/js/comments-anchor.test.mjs` | D (create) | `node --test` coverage of the pure anchoring functions |

---

## Shared Contracts (FROZEN — do not change without updating this plan)

### C1. Asset URLs

```
GET /__reader__/reader.css?v=<version>
GET /__reader__/reader.js?v=<version>
GET /__reader__/comments.js?v=<version>
```

Served from `src/demo_server/static/`, allowlist-only. Templates get the version through
the Jinja variable `reader_version`.

### C2. Template DOM (produced by B, consumed by C and D)

Every one of the three templates must render exactly this structure:

```html
<html lang="{{ lang }}" data-theme="light">
<head>
  ...
  <link rel="stylesheet" href="/__reader__/reader.css?v={{ reader_version }}">
  <script>
  (function () {
    try {
      var ui = JSON.parse(localStorage.getItem('mdr-ui') || '{}');
      if (!ui.theme) {
        var legacy = localStorage.getItem('theme');
        ui.theme = legacy || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
      }
      document.documentElement.setAttribute('data-theme', ui.theme);
      if (ui.skin && ui.skin !== 'default') document.documentElement.setAttribute('data-skin', ui.skin);
    } catch (e) {}
  })();
  </script>
</head>
<body>
  <div id="mdr-rail" class="mdr-rail" role="toolbar" aria-label="Reader tools"></div>
  <aside id="mdr-panel" class="mdr-panel" aria-hidden="true">
    <header class="mdr-panel-head">
      <h2 id="mdr-panel-title" class="mdr-panel-title"></h2>
      <div id="mdr-panel-actions" class="mdr-panel-actions"></div>
      <button id="mdr-panel-close" class="mdr-panel-close" aria-label="Close panel" type="button">&#10005;</button>
    </header>
    <div id="mdr-panel-body" class="mdr-panel-body"></div>
  </aside>
  {{ toc }}
  <div class="md-container" id="mdr-content">
    {{ content }}
  </div>
  <script src="/__reader__/reader.js?v={{ reader_version }}" defer></script>
  <script src="/__reader__/comments.js?v={{ reader_version }}" defer></script>
</body>
</html>
```

Notes:
- The rail is empty in HTML; **all rail buttons are created by JS**.
- `defer` scripts execute in document order, so `reader.js` always runs before
  `comments.js`. `comments.js` must still guard with `MdrRail.ready()` (C3).
- The existing inline `theme-toggle` button and its `toggleTheme()` function are **deleted**
  from `meridian-lite`; the rail replaces them.
- The existing TOC scroll-spy script stays in `meridian-lite` (unchanged, C/D do not touch it).
- `github` and `minimal` currently render no `{{ toc }}`; leave it that way.

### C3. `window.MdrRail` API (implemented by C, consumed by D)

```js
window.MdrRail = {
  // Register a tool. Call before or after DOMContentLoaded; buttons are (re)sorted by `order`.
  register(tool),

  // Panel control
  open(id),            // opens the panel for tool `id` (no-op for type:'button' tools)
  close(),             // closes whatever panel is open
  isOpen(id),          // -> boolean

  // Preferences, persisted to localStorage['mdr-ui'] as JSON {theme, skin}
  getUi(),             // -> {theme: 'light'|'dark', skin: string}
  setUi(patch),        // shallow-merges and re-applies data-theme / data-skin

  // The rendered article element (#mdr-content). Always use this, never a raw selector,
  // because the source toggle swaps the element's children.
  contentEl(),         // -> HTMLElement

  // Runs cb immediately if the rail is already initialized, else on init.
  ready(cb),
};
```

Tool shape:

```js
// Panel tool
{ id: 'comments', icon: '\uD83D\uDCAC', label: 'Comments', order: 30, type: 'panel',
  onOpen: function (bodyEl, actionsEl) {},   // fill both; both are emptied before the call
  onClose: function () {} }                   // optional

// Button tool (no panel)
{ id: 'source', icon: '</>', label: 'Toggle source', order: 40, type: 'button',
  onClick: function (btnEl) {} }
```

Rail order values used in this plan: theme `10`, settings `20`, comments `30`, source `40`.

`MdrRail` also dispatches two `CustomEvent`s on `document` that D listens to:

- `mdr:source-shown` — the source `<pre>` is now displayed.
- `mdr:source-hidden` — the rendered article is back in the DOM.

### C4. CSS class contract (provided by B, used by C and D)

Rail/panel: `.mdr-rail`, `.mdr-rail-btn`, `.mdr-rail-btn.is-active`, `.mdr-panel`,
`.mdr-panel.is-open`, `.mdr-panel-head`, `.mdr-panel-title`, `.mdr-panel-actions`,
`.mdr-panel-close`, `.mdr-panel-body`.

Widgets: `.mdr-btn`, `.mdr-btn.is-primary`, `.mdr-textarea`, `.mdr-empty`,
`.mdr-skin-option`, `.mdr-swatch`.

Comments: `.mdr-comment-hl`, `.mdr-comment-hl.is-active`, `.mdr-selection-btn`,
`.mdr-comment-item`, `.mdr-comment-item.is-active`, `.mdr-comment-item.is-orphan`,
`.mdr-comment-quote`, `.mdr-comment-text`, `.mdr-comment-actions`.

Source: `.mdr-source`, `body.mdr-source-mode` (B hides `.toc` under this class).

### C5. localStorage keys

- `mdr-ui` → `{"theme":"light|dark","skin":"default|github|solarized|dracula|nord|sepia"}`
- `mdr-comments:<location.pathname>` → array of
  `{id, quote:{exact,prefix,suffix}, text, createdAt, updatedAt}`

### C6. Skin ids

`default` (theme's own palette), `github`, `solarized`, `dracula`, `nord`, `sepia`.

---

# Workstream A — Backend (Python)

Owns: `pages.py`, `static_files.py`, `server.py`, `markdown_render.py`, `pyproject.toml`, `tests/`.

### Task A1: Test scaffolding

**Files:**
- Create: `tests/__init__.py` (empty), `tests/conftest.py`

- [ ] **Step 1: Create the shared fixtures**

`tests/__init__.py` is empty (it makes `from tests.conftest import PASSCODE` importable).

`tests/conftest.py`:

```python
"""Shared pytest fixtures: a temporary DemoDocs-like tree and a TestClient."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from demo_server.server import create_app, hash_passcode

PASSCODE = "s3cret"


@pytest.fixture()
def docs_root(tmp_path):
    """A base dir with one open module and one encrypted module."""
    open_mod = tmp_path / "open-mod"
    (open_mod / "sub").mkdir(parents=True)
    (open_mod / "index.html").write_text("<h1>open index</h1>")
    (open_mod / "notes.md").write_text("# Notes\n\nhello world\n")
    (open_mod / "sub" / "deep.html").write_text("<h1>deep</h1>")

    enc_mod = tmp_path / "enc-mod"
    (enc_mod / "sub").mkdir(parents=True)
    (enc_mod / ".encrypt").write_text(hash_passcode(PASSCODE))
    (enc_mod / "index.html").write_text("<h1>enc index</h1>")
    (enc_mod / "secret.md").write_text("# Secret\n\nclassified\n")
    (enc_mod / "sub" / "deep.html").write_text("<h1>enc deep</h1>")
    return tmp_path


@pytest.fixture()
def client(docs_root):
    return TestClient(create_app(str(docs_root)))
```

- [ ] **Step 2: Verify collection works**

Run: `cd ~/LinkedIn/demo-server && python -m pytest tests -q`
Expected: `no tests ran` (exit code 5) — no collection errors.

- [ ] **Step 3: Commit**

```bash
git add tests/__init__.py tests/conftest.py
git commit -m "test: add pytest fixtures for demo-server"
```

### Task A2: `safe_next` validation

**Files:**
- Modify: `src/demo_server/server.py`
- Test: `tests/test_auth_next.py`

- [ ] **Step 1: Write the failing tests**

```python
"""Unit tests for post-login redirect target validation."""

from __future__ import annotations

import pytest

from demo_server.server import safe_next


@pytest.mark.parametrize(
    "candidate",
    [
        "/enc-mod/",
        "/enc-mod/sub/deep.html",
        "/enc-mod/notes.md?raw=1",
        "/enc-mod",
    ],
)
def test_safe_next_accepts_in_module_paths(candidate):
    assert safe_next(candidate, "enc-mod") == candidate


@pytest.mark.parametrize(
    "candidate",
    [
        "",
        None,
        "https://evil.com/",
        "//evil.com/",
        "/\\evil.com",
        "\\\\evil.com",
        "/other-mod/index.html",
        "/enc-mod/../other-mod/index.html",
        "/enc-mod-evil/index.html",
        "enc-mod/index.html",
        "/enc-mod/\nSet-Cookie: x=1",
    ],
)
def test_safe_next_rejects_hostile_targets(candidate):
    assert safe_next(candidate, "enc-mod") == "/enc-mod/"


def test_safe_next_root_scope():
    assert safe_next("/all/", "__root__") == "/all/"
    assert safe_next("/enc-mod/", "__root__") == "/all/"
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_auth_next.py -q`
Expected: FAIL — `ImportError: cannot import name 'safe_next'`.

- [ ] **Step 3: Implement `safe_next` in `server.py`**

Add `import posixpath`, `from typing import Optional`, and
`from urllib.parse import urlsplit` to the import block, then:

```python
def safe_next(candidate: Optional[str], module: str) -> str:
    """Validate a post-login redirect target.

    Only same-origin paths that stay inside ``module`` are allowed. Anything
    else — absolute URLs, protocol-relative URLs, backslash tricks, ``..``
    escapes, header-injection attempts — falls back to the module root.
    ``module`` may be the sentinel ``__root__``, whose scope is ``/all/``.
    """
    fallback = "/all/" if module == "__root__" else "/{0}/".format(module)
    if not candidate or not isinstance(candidate, str):
        return fallback
    # Reject control characters outright (CR/LF header injection, NUL).
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        return fallback
    if "\\" in candidate:
        return fallback
    if not candidate.startswith("/") or candidate.startswith("//"):
        return fallback
    parts = urlsplit(candidate)
    if parts.scheme or parts.netloc:
        return fallback
    normalized = posixpath.normpath(parts.path)
    scope = "/all" if module == "__root__" else "/{0}".format(module)
    if normalized != scope and not normalized.startswith(scope + "/"):
        return fallback
    return candidate
```

- [ ] **Step 4: Run to verify it passes**

Run: `python -m pytest tests/test_auth_next.py -q`
Expected: PASS (16 passed).

- [ ] **Step 5: Commit**

```bash
git add src/demo_server/server.py tests/test_auth_next.py
git commit -m "feat: add safe_next redirect-target validation"
```

### Task A3: Extract HTML pages into `pages.py`

**Files:**
- Create: `src/demo_server/pages.py`
- Modify: `src/demo_server/server.py`

- [ ] **Step 1: Create `pages.py`**

Move these verbatim out of `server.py` into a new `src/demo_server/pages.py`:
`WELCOME_PAGE`, `REDIRECT_PAGE`, `ASSETS_DIR`, `_redirect_cat_cache`,
`_redirect_cat_svg()`, and `_render_redirect()` (renamed to a public
`render_redirect()`, same signature). Replace `PASSCODE_FORM` with the new responsive
page below. Module header:

```python
"""Standalone HTML pages: passcode, welcome listing, and move-redirect."""

from __future__ import annotations

import html
import json
from pathlib import Path
```

Then the new passcode page (replacing `PASSCODE_FORM` entirely):

```python
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
```

Note: `%%MODULE_ATTR%%` must be replaced **before** `%%MODULE%%`, otherwise the shorter
token matches inside the longer one. The order above is correct — keep it.

- [ ] **Step 2: Update `server.py` to use `pages.py`**

- Delete `PASSCODE_FORM`, `WELCOME_PAGE`, `REDIRECT_PAGE`, `ASSETS_DIR`,
  `_redirect_cat_cache`, `_redirect_cat_svg`, `_render_redirect` from `server.py`.
- Keep `import html` and `import json` in `server.py` — `_render_section` and
  `_load_config` still use them.
- Add `from demo_server import pages`.
- Replace each `PASSCODE_FORM.format(module=X, error=Y)` with
  `pages.render_passcode_page(X, next_url, Y)`; the exact `next_url` per call site is
  specified in Task A4. Until A4 lands, pass `""`.
- Replace `WELCOME_PAGE.format(...)` with
  `pages.render_welcome_page(len(mtimes), modules_html)`.
- Replace `_render_redirect(...)` with `pages.render_redirect(...)`.

- [ ] **Step 3: Verify nothing broke**

Run: `python -m pytest tests -q && python -c "from demo_server.server import create_app; create_app('/tmp')"`
Expected: tests PASS, import clean.

- [ ] **Step 4: Commit**

```bash
git add src/demo_server/pages.py src/demo_server/server.py
git commit -m "refactor: extract HTML pages into pages.py, responsive passcode page"
```

### Task A4: Wire `next` through the login flow

**Files:**
- Modify: `src/demo_server/server.py`
- Test: `tests/test_auth_next.py`

- [ ] **Step 1: Write the failing integration tests**

Append to `tests/test_auth_next.py`:

```python
from tests.conftest import PASSCODE  # noqa: E402


def test_deep_path_401_carries_next(client):
    r = client.get("/enc-mod/sub/deep.html")
    assert r.status_code == 401
    assert 'name="next" value="/enc-mod/sub/deep.html"' in r.text


def test_login_redirects_to_next(client):
    r = client.post(
        "/enc-mod/__auth__",
        data={"passcode": PASSCODE, "next": "/enc-mod/sub/deep.html"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/enc-mod/sub/deep.html"


def test_login_rejects_offsite_next(client):
    r = client.post(
        "/enc-mod/__auth__",
        data={"passcode": PASSCODE, "next": "https://evil.com/"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/enc-mod/"


def test_login_without_next_uses_module_root(client):
    r = client.post(
        "/enc-mod/__auth__", data={"passcode": PASSCODE}, follow_redirects=False
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/enc-mod/"


def test_wrong_passcode_preserves_next(client):
    r = client.post(
        "/enc-mod/__auth__",
        data={"passcode": "nope", "next": "/enc-mod/sub/deep.html"},
    )
    assert r.status_code == 403
    assert 'name="next" value="/enc-mod/sub/deep.html"' in r.text
    assert "Wrong passcode" in r.text


def test_query_string_preserved_in_next(client):
    r = client.get("/enc-mod/secret.md?raw=1")
    assert r.status_code == 401
    assert 'value="/enc-mod/secret.md?raw=1"' in r.text
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_auth_next.py -q`
Expected: FAIL on the new tests (no `next` field yet).

- [ ] **Step 3: Implement**

Add a helper next to `safe_next` in `server.py`:

```python
def _request_target(request: Request) -> str:
    """The path (plus query) the reader actually asked for."""
    target = request.url.path
    if request.url.query:
        target = target + "?" + request.url.query
    return target
```

In `serve()`, the encrypt-check failure branch becomes:

```python
            if value != module:
                return HTMLResponse(
                    pages.render_passcode_page(module, _request_target(request)),
                    status_code=401,
                )
```

In `auth()`:

```python
    @app.post("/{module}/__auth__")
    async def auth(
        module: str,
        request: Request,
        passcode: str = Form(...),
        next: str = Form(""),
    ):
        ...
        if not verify_passcode(passcode, stored):
            return HTMLResponse(
                pages.render_passcode_page(
                    module, safe_next(next, module), "Wrong passcode."
                ),
                status_code=403,
            )

        response = RedirectResponse(safe_next(next, module), status_code=303)
```

In `listing()`, the root-auth failure branch:

```python
            if value != "__root__":
                return HTMLResponse(
                    pages.render_passcode_page("all", "/all/"), status_code=401
                )
```

In `root_auth()`, accept `next: str = Form("")`, redirect to
`safe_next(next, "__root__")`, and on a wrong passcode render
`pages.render_passcode_page("all", safe_next(next, "__root__"), "Wrong passcode.")`.
The root form's action must stay `/all/__auth__`, which
`render_passcode_page("all", ...)` produces — keep the module name `"all"`.

- [ ] **Step 4: Run to verify it passes**

Run: `python -m pytest tests -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/demo_server/server.py tests/test_auth_next.py
git commit -m "feat: preserve requested URL across passcode login"
```

### Task A5: Reader static-asset route

**Files:**
- Create: `src/demo_server/static_files.py`, `src/demo_server/static/`
- Modify: `src/demo_server/server.py`, `pyproject.toml`
- Test: `tests/test_raw_and_assets.py`

- [ ] **Step 1: Write the failing tests**

```python
"""Tests for the /__reader__/ asset route and the ?raw=1 source view."""

from __future__ import annotations

from tests.conftest import PASSCODE


def test_reader_asset_served(client):
    r = client.get("/__reader__/reader.css")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/css")
    assert "immutable" in r.headers.get("cache-control", "")


def test_reader_asset_js_served(client):
    for name in ("reader.js", "comments.js"):
        r = client.get("/__reader__/" + name)
        assert r.status_code == 200
        assert "javascript" in r.headers["content-type"]


def test_reader_asset_rejects_unknown_file(client):
    assert client.get("/__reader__/secrets.txt").status_code == 404


def test_reader_asset_rejects_traversal(client):
    for path in ("/__reader__/../server.py", "/__reader__/%2e%2e/server.py"):
        assert client.get(path).status_code in (403, 404)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_raw_and_assets.py -q`
Expected: FAIL — the catch-all treats `/__reader__` as a module and 404s.

- [ ] **Step 3: Implement `static_files.py`**

```python
"""Allowlisted static assets for the Markdown reader UI."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

STATIC_DIR = Path(__file__).resolve().parent / "static"

# filename -> media type. Nothing outside this mapping is ever served.
ALLOWED = {
    "reader.css": "text/css; charset=utf-8",
    "reader.js": "application/javascript; charset=utf-8",
    "comments.js": "application/javascript; charset=utf-8",
}

_version_cache = None  # type: Optional[str]


def reader_version() -> str:
    """Cache-busting token for asset URLs: the installed package version."""
    global _version_cache
    if _version_cache is None:
        try:
            from importlib.metadata import version

            _version_cache = version("demo-server")
        except Exception:
            _version_cache = "dev"
    return _version_cache


def asset_path(filename: str) -> Optional[Path]:
    """Resolve an allowlisted asset, or None."""
    if filename not in ALLOWED:
        return None
    path = STATIC_DIR / filename
    return path if path.is_file() else None
```

- [ ] **Step 4: Register the route in `server.py`**

Add `from demo_server import static_files` and register this **before**
`@app.post("/{module}/__auth__")` — FastAPI matches in registration order:

```python
    @app.get("/__reader__/{filename}")
    async def reader_asset(filename: str):
        path = static_files.asset_path(filename)
        if path is None:
            return HTMLResponse("Not found", status_code=404)
        return FileResponse(
            path,
            media_type=static_files.ALLOWED[filename],
            headers={"Cache-Control": "public, max-age=31536000, immutable"},
        )
```

- [ ] **Step 5: Add package data**

In `pyproject.toml`:

```toml
[tool.setuptools.package-data]
demo_server = ["themes/**/*.html", "static/*", "assets/*"]
```

- [ ] **Step 6: Create placeholder assets so the tests can pass**

Workstreams B, C and D fill these in; A only needs them to exist. Create
`src/demo_server/static/reader.css`, `src/demo_server/static/reader.js`, and
`src/demo_server/static/comments.js`, each containing a single `/* placeholder */`
line. **If a file already exists with real content, leave it alone.**

- [ ] **Step 7: Run to verify it passes**

Run: `python -m pytest tests/test_raw_and_assets.py -q`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/demo_server/static_files.py src/demo_server/static src/demo_server/server.py pyproject.toml tests/test_raw_and_assets.py
git commit -m "feat: serve allowlisted reader assets from /__reader__/"
```

### Task A6: `?raw=1` source view

**Files:**
- Modify: `src/demo_server/server.py`
- Test: `tests/test_raw_and_assets.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_raw_and_assets.py`:

```python
def test_raw_returns_plain_markdown(client):
    r = client.get("/open-mod/notes.md?raw=1")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert r.text == "# Notes\n\nhello world\n"


def test_without_raw_returns_rendered_html(client):
    r = client.get("/open-mod/notes.md")
    assert r.status_code == 200
    assert "<h1" in r.text


def test_raw_ignored_for_non_markdown(client):
    r = client.get("/open-mod/index.html?raw=1")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")


def test_raw_still_requires_passcode(client):
    r = client.get("/enc-mod/secret.md?raw=1")
    assert r.status_code == 401
    assert "classified" not in r.text


def test_raw_works_after_login(client):
    client.post(
        "/enc-mod/__auth__", data={"passcode": PASSCODE, "next": "/enc-mod/"}
    )
    r = client.get("/enc-mod/secret.md?raw=1")
    assert r.status_code == 200
    assert "classified" in r.text
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_raw_and_assets.py -q`
Expected: FAIL — `?raw=1` currently returns rendered HTML.

- [ ] **Step 3: Implement**

Add `PlainTextResponse` to the `fastapi.responses` import, then change the Markdown
branch at the end of `serve()` — which already sits **after** the passcode, hidden-file
and traversal checks; do not move it:

```python
        if file_path.suffix == ".md":
            if request.query_params.get("raw"):
                return PlainTextResponse(
                    file_path.read_text(encoding="utf-8"),
                    media_type="text/plain; charset=utf-8",
                )
            from demo_server.markdown_render import render_md_file

            html_content = render_md_file(file_path)
            return HTMLResponse(html_content)
```

- [ ] **Step 4: Run to verify it passes**

Run: `python -m pytest tests -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/demo_server/server.py tests/test_raw_and_assets.py
git commit -m "feat: serve raw Markdown source via ?raw=1"
```

### Task A7: Pass `reader_version` to templates

**Files:**
- Modify: `src/demo_server/markdown_render.py`
- Test: `tests/test_raw_and_assets.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_raw_and_assets.py`:

```python
def test_rendered_page_links_reader_assets(client):
    r = client.get("/open-mod/notes.md")
    assert "/__reader__/reader.css?v=" in r.text
    assert "/__reader__/reader.js?v=" in r.text
    assert "/__reader__/comments.js?v=" in r.text
    assert 'id="mdr-rail"' in r.text
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_raw_and_assets.py::test_rendered_page_links_reader_assets -q`
Expected: FAIL — templates are Workstream B's half.

- [ ] **Step 3: Implement the render-side half**

In `markdown_render.py` add:

```python
from demo_server.static_files import reader_version
```

and add to the `template.render(...)` call in `render_md_file`:

```python
        reader_version=reader_version(),
```

- [ ] **Step 4: Verify**

Run: `python -m pytest tests -q`
Expected: everything passes except `test_rendered_page_links_reader_assets`, which stays
red until Workstream B lands. If you must commit before B lands, mark it
`@pytest.mark.xfail(reason="needs workstream B templates", strict=False)` and note that
the integration step removes the marker.

- [ ] **Step 5: Commit**

```bash
git add src/demo_server/markdown_render.py tests/test_raw_and_assets.py
git commit -m "feat: expose reader_version to Markdown templates"
```

---

# Workstream B — Styles and Templates

Owns: `src/demo_server/static/reader.css` and the three `themes/*/template.html`.
**Do not edit any `.py` file.** If `static/reader.css` already exists containing
`/* placeholder */`, overwrite it. If `src/demo_server/static/` does not exist yet,
create it.

Reference source to port palettes from (read-only, different repo):
`/Users/ckuo/project/chrome-swiss-knife/markdown-reader/styles/skins.css`

### Task B1: Variable contract + rail/panel CSS

**Files:**
- Create/overwrite: `src/demo_server/static/reader.css`

- [ ] **Step 1: Write the base layer**

Start with a documentation header explaining that themes own layout and skins own color.
Then style everything **only** through the variable contract — `--bg --surface --text
--text-sec --text-muted --primary --primary-hover --primary-light --accent
--accent-light --warn --warn-light --danger --border --border-strong --shadow
--shadow-md --radius --radius-sm` — always with a literal fallback
(`var(--surface, #fff)`) so a theme that misses a variable still degrades sanely.

Implement every class in contract C4:

- `.mdr-rail` — `position: fixed; top: 1rem; right: 1rem; z-index: 60;` vertical flex,
  `gap: .5rem`. Must sit above `.toc` (z-index 40).
- `.mdr-rail-btn` — 40×40 circle, `background: var(--surface)`,
  `border: 1px solid var(--border)`, `box-shadow: var(--shadow)`, hover
  `border-color: var(--primary)`; `.is-active` uses `--primary-light` background and
  `--primary` text. Include a visible `:focus-visible` ring.
- `.mdr-panel` — `position: fixed; top: 0; right: 0; height: 100vh; height: 100dvh;
  width: 320px; z-index: 70; transform: translateX(100%); transition: transform .18s ease;`
  `background: var(--surface)`, left border, `display: flex; flex-direction: column;`
  `.is-open { transform: translateX(0); }`.
- `.mdr-panel-head` — flex row: title, actions, close button; bottom border; padding.
- `.mdr-panel-body` — `flex: 1; overflow-y: auto; padding: 1rem;`.
- `body.mdr-panel-open .mdr-rail { right: calc(320px + 1rem); }` so the rail stays
  clickable while a panel is open.
- `.mdr-btn`, `.mdr-btn.is-primary`, `.mdr-textarea`, `.mdr-empty` — small utilities.
- `.mdr-skin-option` — flex row with `.mdr-swatch` (18×18 rounded square) and a label;
  selected state keyed off `[aria-checked="true"]`.
- `.mdr-comment-hl` — `background: var(--warn-light); border-bottom: 2px solid
  var(--warn); cursor: pointer;`; `.is-active` intensifies.
- `.mdr-selection-btn` — `position: absolute; z-index: 80;` small pill button.
- `.mdr-comment-item` (+ `.is-active`, `.is-orphan`), `.mdr-comment-quote` (2-line
  clamp, italic, `--text-muted`), `.mdr-comment-text`, `.mdr-comment-actions`.
  `.is-orphan` gets a dashed `--warn` left border and reduced opacity.
- `.mdr-source` — `white-space: pre-wrap; word-break: break-word; font-family:
  var(--font-m, ui-monospace, SFMono-Regular, Menlo, monospace); font-size: .85rem;
  line-height: 1.6;` in a bordered `--surface` block.
- `body.mdr-source-mode .toc { display: none; }`.
- Below 640px the panel becomes a bottom sheet: `top: auto; bottom: 0; width: 100%;
  height: 70vh; border-left: none; border-top: 1px solid var(--border);
  border-radius: 16px 16px 0 0; transform: translateY(100%);` with
  `.is-open { transform: translateY(0); }` and
  `body.mdr-panel-open .mdr-rail { right: 1rem; }`.
- `@media (prefers-reduced-motion: reduce)` disables the panel transition.

- [ ] **Step 2: Verify the file parses**

Run: `python -c "import pathlib;s=pathlib.Path('src/demo_server/static/reader.css').read_text();assert s.count('{')==s.count('}'), 'unbalanced braces';print('ok',len(s))"`
Expected: `ok <n>`

- [ ] **Step 3: Commit**

```bash
git add src/demo_server/static/reader.css
git commit -m "feat: add reader.css base layer (rail, panel, comments, source)"
```

### Task B2: Port the five skins

**Files:**
- Modify: `src/demo_server/static/reader.css`

- [ ] **Step 1: Read the reference palettes**

Read `/Users/ckuo/project/chrome-swiss-knife/markdown-reader/styles/skins.css`. Each skin
appears twice: a light face on `.mdr-root[data-skin="X"]` and a dark face on
`.mdr-root[data-skin="X"][data-theme="dark"]`.

- [ ] **Step 2: Port them**

For `github`, `solarized`, `dracula`, `nord`, `sepia`, copy the variable values verbatim
and rewrite the selectors:

```
.mdr-root[data-skin="github"]                       ->  html[data-skin="github"]
.mdr-root[data-skin="github"][data-theme="dark"]    ->  html[data-skin="github"][data-theme="dark"]
```

Rules:
- Palette variables only. **Drop** `.mdr-root`-scoped layout tweaks (e.g. the `sepia`
  `.md-container` width rule) — layout belongs to the theme.
- Map any reference variable with no counterpart onto the closest contract variable;
  do not invent new contract variables.
- Comment each block with its source file and skin name.
- `html[data-skin="X"]` is specificity (0,1,1) and beats a template's `:root` (0,1,0)
  regardless of load order. Do **not** use `!important`.
- There is no `default` block — an absent `data-skin` means the theme's own palette.

- [ ] **Step 3: Verify all skins are present**

Run: `grep -c 'html\[data-skin=' src/demo_server/static/reader.css`
Expected: `10` (5 skins × light + dark).

- [ ] **Step 4: Commit**

```bash
git add src/demo_server/static/reader.css
git commit -m "feat: port github/solarized/dracula/nord/sepia skins"
```

### Task B3: Update the meridian-lite template

**Files:**
- Modify: `src/demo_server/themes/meridian-lite/template.html`

- [ ] **Step 1: Apply the C2 DOM contract**

- Add the `reader.css` `<link>` and the bootstrap `<script>` to `<head>`, exactly as in
  contract C2.
- Delete the `.theme-toggle` CSS block, the `<button class="theme-toggle">` element, the
  `toggleTheme()` function, and the old `localStorage.getItem('theme')` IIFE — the
  bootstrap snippet and the rail replace them.
- Add `#mdr-rail` and `#mdr-panel` (full markup from C2) and `id="mdr-content"` on
  `.md-container`.
- Add the two `<script defer>` tags at the end of `<body>`.
- Keep the TOC markup, the TOC CSS, the TOC scroll-spy script, and every existing prose
  rule untouched.
- Its `:root` / `[data-theme="dark"]` blocks stay — they are the `default` skin.

- [ ] **Step 2: Verify**

```bash
python - <<'PY'
from demo_server.markdown_render import get_template
h = get_template("meridian-lite").render(title="t", content="<p>c</p>", toc="",
                                         highlight_css="", lang="en", reader_version="1")
for needle in ['id="mdr-rail"', 'id="mdr-panel"', 'id="mdr-content"',
               '/__reader__/reader.css?v=1', '/__reader__/reader.js?v=1',
               '/__reader__/comments.js?v=1', 'mdr-ui']:
    assert needle in h, needle
assert "toggleTheme" not in h
print("meridian-lite ok")
PY
```
Expected: `meridian-lite ok`

- [ ] **Step 3: Commit**

```bash
git add src/demo_server/themes/meridian-lite/template.html
git commit -m "feat: mount reader rail in meridian-lite theme"
```

### Task B4: Variabilize and update the github template

**Files:**
- Modify: `src/demo_server/themes/github/template.html`

- [ ] **Step 1: Replace hardcoded colors with the contract**

- Add a `:root { ... }` block defining every contract variable using the template's
  **existing** GitHub-light colors, then replace each literal color elsewhere in the
  stylesheet with the matching `var(--x)`.
- Add a `[data-theme="dark"]` block using GitHub's dark-dimmed values — take them from
  the `github` dark face in the reference `skins.css`, which is exactly this palette.
- Add `data-theme="light"` to the `<html>` tag.
- Apply the full C2 DOM contract (link, bootstrap, rail, panel, `#mdr-content`, scripts).
- Do **not** add a TOC; this theme renders none.
- Colors only — no layout, spacing, or typography changes.

- [ ] **Step 2: Verify**

Run: `grep -nE '#[0-9a-fA-F]{3,8}' src/demo_server/themes/github/template.html | grep -vE '^\s*[0-9]+:\s*--'`
Expected: only lines inside the `:root` / `[data-theme="dark"]` variable blocks.

Then run the B3 render check with `get_template("github")` (drop the `toggleTheme`
assertion; that theme never had one).

- [ ] **Step 3: Commit**

```bash
git add src/demo_server/themes/github/template.html
git commit -m "feat: variabilize github theme, add dark face and reader rail"
```

### Task B5: Variabilize and update the minimal template

**Files:**
- Modify: `src/demo_server/themes/minimal/template.html`

- [ ] **Step 1: Same treatment as B4**

Identical procedure applied to `minimal`: derive `:root` from its current colors; add a
hand-picked `[data-theme="dark"]` face (dark grey surface, off-white text, borrowing
meridian-lite's dark `--border` and `--primary` so code blocks stay legible); add
`data-theme="light"` on `<html>`; apply the C2 DOM contract; no TOC; no layout changes.

- [ ] **Step 2: Verify**

Run the B4 grep against `minimal/template.html`, then the render check with
`get_template("minimal")`.

- [ ] **Step 3: Commit**

```bash
git add src/demo_server/themes/minimal/template.html
git commit -m "feat: variabilize minimal theme, add dark face and reader rail"
```

---

# Workstream C — `reader.js` (rail, settings, source)

Owns exactly one file: `src/demo_server/static/reader.js`. **Do not edit anything else.**
If it exists containing `/* placeholder */`, overwrite it. Create
`src/demo_server/static/` if missing.

### Task C1: Rail core + `window.MdrRail`

**Files:**
- Create/overwrite: `src/demo_server/static/reader.js`

- [ ] **Step 1: Implement the rail**

One IIFE, no dependencies, no build step, ES5-compatible syntax (`var`, `function`).
Implement contract C3 exactly:

- State: `tools` (array), `openId` (string|null), `initialized` (bool), `readyCbs`.
- `getUi()` reads `localStorage['mdr-ui']`, JSON-parses defensively, and defaults to
  `{theme: document.documentElement.getAttribute('data-theme') || 'light', skin: 'default'}`.
  On first read, migrate a legacy `localStorage['theme']` value into `mdr-ui`, then
  `localStorage.removeItem('theme')`.
- `setUi(patch)` shallow-merges, persists, and applies:
  `documentElement.setAttribute('data-theme', ui.theme)`; for skin, `setAttribute('data-skin', skin)`
  when it is not `'default'`, else `removeAttribute('data-skin')`.
- `register(tool)` pushes, sorts by `order`, re-renders the rail when already initialized.
- Rail rendering: per tool create
  `<button class="mdr-rail-btn" type="button" data-tool="<id>" aria-label="<label>" title="<label>">`
  containing the icon. Panel tools also get `aria-controls="mdr-panel"` and
  `aria-expanded="false"`.
- `open(id)`: close any current panel (calling its `onClose`), set `#mdr-panel-title` to
  the tool label, empty `#mdr-panel-body` and `#mdr-panel-actions`, call
  `onOpen(bodyEl, actionsEl)`, add `.is-open` to the panel, set `aria-hidden="false"`,
  add `mdr-panel-open` to `document.body`, set the button's `.is-active` and
  `aria-expanded="true"`, move focus into the panel.
- `close()`: reverse all of the above and return focus to the tool's button.
- Clicking an already-open tool's button closes it. Esc closes. A click outside both the
  panel and the rail closes it.
- `contentEl()` returns `document.getElementById('mdr-content')`.
- `ready(cb)` queues or runs immediately.
- A page without `#mdr-rail` must degrade to a silent no-op, never throw.

- [ ] **Step 2: Register the theme toggle (order 10)**

```js
MdrRail.register({
  id: 'theme', icon: '\uD83C\uDF13', label: 'Toggle dark mode', order: 10,
  type: 'button',
  onClick: function () {
    var ui = MdrRail.getUi();
    MdrRail.setUi({ theme: ui.theme === 'dark' ? 'light' : 'dark' });
  },
});
```

- [ ] **Step 3: Syntax check**

Run: `node --check src/demo_server/static/reader.js`
Expected: exit 0, no output.

- [ ] **Step 4: Commit**

```bash
git add src/demo_server/static/reader.js
git commit -m "feat: add reader rail core and theme toggle"
```

### Task C2: Settings panel

**Files:**
- Modify: `src/demo_server/static/reader.js`

- [ ] **Step 1: Implement**

Register `{id:'settings', icon:'\u2699', label:'Settings', order:20, type:'panel'}`.
`onOpen(body)` builds:

- Section "Appearance": a light/dark segmented control calling `MdrRail.setUi({theme})`,
  re-reading `getUi()` each time the panel opens so it stays in sync with the rail
  toggle.
- Section "Skin": a `role="radiogroup"` containing one
  `<button class="mdr-skin-option" role="radio" aria-checked="...">` per entry of:

```js
var SKINS = [
  { id: 'default',   name: 'Theme default', bg: 'var(--bg)', fg: 'var(--primary)' },
  { id: 'github',    name: 'GitHub',        bg: '#ffffff',   fg: '#0969da' },
  { id: 'solarized', name: 'Solarized',     bg: '#fdf6e3',   fg: '#268bd2' },
  { id: 'dracula',   name: 'Dracula',       bg: '#282a36',   fg: '#bd93f9' },
  { id: 'nord',      name: 'Nord',          bg: '#2e3440',   fg: '#88c0d0' },
  { id: 'sepia',     name: 'Sepia',         bg: '#f4ecd8',   fg: '#8b5a2b' },
];
```

Each option shows a `.mdr-swatch` styled inline with
`background: linear-gradient(135deg, <bg> 50%, <fg> 50%)`. Selecting one calls
`MdrRail.setUi({skin: id})` and updates `aria-checked` across the group. Arrow keys move
between radio options (standard radiogroup keyboard behavior).

- [ ] **Step 2: Syntax check**

Run: `node --check src/demo_server/static/reader.js`
Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add src/demo_server/static/reader.js
git commit -m "feat: add settings panel with skin picker"
```

### Task C3: Source toggle

**Files:**
- Modify: `src/demo_server/static/reader.js`

- [ ] **Step 1: Implement**

Register `{id:'source', icon:'</>', label:'Toggle source', order:40, type:'button'}`.

```js
var sourceState = { text: null, shown: false, rendered: null, pre: null, loading: false };
```

`onClick` behavior:

1. If `sourceState.shown` → restore: remove the `<pre>`, re-append the saved rendered
   nodes to `#mdr-content`, remove `body.mdr-source-mode`, clear `.is-active`, then
   `document.dispatchEvent(new CustomEvent('mdr:source-hidden'))`.
2. Else if `sourceState.text === null` and not loading → set `loading`, set the button
   `aria-busy="true"`, `fetch(location.pathname + '?raw=1', {credentials: 'same-origin'})`.
   - If the response is not OK, or its `content-type` is not `text/plain`, the session
     has expired and the server returned the login page. Do **not** display it as
     source — call `location.reload()` so the reader lands on the passcode page.
   - On network failure, insert a transient
     `<div class="mdr-empty">Could not load source.</div>` above `#mdr-content`,
     auto-removed after 4s, and leave the rendered view up.
3. On success: save `Array.prototype.slice.call(contentEl.childNodes)` into
   `sourceState.rendered` and **detach** them (never destroy — comment highlight spans
   must survive), append `<pre class="mdr-source">` with
   `textContent = sourceState.text`, add `body.mdr-source-mode`, set `.is-active`, and
   dispatch `mdr:source-shown`.

The fetched text is cached for the page's lifetime.

- [ ] **Step 2: Syntax check**

Run: `node --check src/demo_server/static/reader.js`
Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add src/demo_server/static/reader.js
git commit -m "feat: add source toggle backed by ?raw=1"
```

---

# Workstream D — `comments.js`

Owns `src/demo_server/static/comments.js` and `tests/js/comments-anchor.test.mjs`.
**Do not edit anything else.** If `comments.js` exists containing `/* placeholder */`,
overwrite it. Create `src/demo_server/static/` and `tests/js/` if missing.

Reference implementation to port (read-only, different repo):
`/Users/ckuo/project/chrome-swiss-knife/markdown-reader/src/comments.js`

### Task D1: Port the pure anchoring functions (TDD)

**Files:**
- Create: `tests/js/comments-anchor.test.mjs`
- Create/overwrite: `src/demo_server/static/comments.js`

- [ ] **Step 1: Write the failing tests**

```js
import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const C = require("../../src/demo_server/static/comments.js");

const TEXT = "alpha beta gamma beta delta beta epsilon";

test("captureQuote records exact text with affixes", () => {
  const q = C.captureQuote(TEXT, 6, 10);
  assert.equal(q.exact, "beta");
  assert.equal(q.prefix, "alpha ");
  assert.equal(q.suffix.slice(0, 6), " gamma");
});

test("resolveQuote finds a unique match", () => {
  const q = C.captureQuote("one two three", 4, 7);
  assert.deepEqual(C.resolveQuote("one two three", q), { start: 4, end: 7 });
});

test("resolveQuote disambiguates repeats using affixes", () => {
  const q = C.captureQuote(TEXT, 17, 21); // the second "beta"
  assert.deepEqual(C.resolveQuote(TEXT, q), { start: 17, end: 21 });
});

test("resolveQuote survives edits away from the anchor", () => {
  const q = C.captureQuote(TEXT, 17, 21);
  const edited = "PREFIX ADDED " + TEXT;
  assert.deepEqual(C.resolveQuote(edited, q), { start: 30, end: 34 });
});

test("resolveQuote returns null when the text is gone", () => {
  const q = C.captureQuote(TEXT, 6, 10);
  assert.equal(C.resolveQuote("nothing matching here", q), null);
});

test("newCommentId is unique and prefixed", () => {
  const a = C.newCommentId();
  const b = C.newCommentId();
  assert.match(a, /^c_[0-9a-z]+$/);
  assert.notEqual(a, b);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ~/LinkedIn/demo-server && node --test tests/js/`
Expected: FAIL — module not found / exports missing.

- [ ] **Step 3: Port the pure layer**

Create `comments.js` using the same UMD wrapper as the reference, so it works both as a
browser global and as a CommonJS module in tests. The factory must not touch
`document`/`window` at load time.

```js
// UMD: browser global MdrComments; CommonJS require for pure-function tests.
// Anchoring logic ported from chrome-swiss-knife/markdown-reader/src/comments.js.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.MdrComments = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";
  var AFFIX = 32;
  // captureQuote, affixScore, resolveQuote, buildTextIndex,
  // domPointToOffset, wrapRange, newCommentId
  return {
    captureQuote: captureQuote,
    affixScore: affixScore,
    resolveQuote: resolveQuote,
    buildTextIndex: buildTextIndex,
    domPointToOffset: domPointToOffset,
    newCommentId: newCommentId,
    // DOM + UI functions are added in D2/D3
  };
});
```

Port `captureQuote`, `affixScore`, `resolveQuote`, `buildTextIndex`,
`domPointToOffset`, and the range-wrapping helper verbatim from the reference — they are
already dependency-free. `newCommentId` returns
`"c_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 7)`.

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/js/`
Expected: 6 passing.

- [ ] **Step 5: Commit**

```bash
git add src/demo_server/static/comments.js tests/js/comments-anchor.test.mjs
git commit -m "feat: port comment anchoring functions with node tests"
```

### Task D2: Storage + highlight rendering

**Files:**
- Modify: `src/demo_server/static/comments.js`

- [ ] **Step 1: Implement the storage layer**

Inside the factory, still framework-free:

```js
function storageKey() { return "mdr-comments:" + location.pathname; }

function loadComments() {
  try {
    var v = JSON.parse(localStorage.getItem(storageKey()) || "[]");
    return Array.isArray(v) ? v : [];
  } catch (e) { return []; }
}

function saveComments(list) {
  try { localStorage.setItem(storageKey(), JSON.stringify(list)); } catch (e) {}
}
```

Record shape: `{id, quote:{exact,prefix,suffix}, text, createdAt, updatedAt}` with
second-resolution Unix timestamps.

- [ ] **Step 2: Implement highlight rendering**

`renderHighlights(rootEl, comments)`:

- Build the text index with `buildTextIndex(rootEl)`.
- For each comment, `resolveQuote(index.text, c.quote)`. Unresolved → set
  `c.orphan = true` **in memory only** (never persisted) and skip highlighting.
- Wrap each resolved range in `<span class="mdr-comment-hl" data-id="<id>">`.
- Process **longest match first** and rebuild the index after each wrap, because wrapping
  splits text nodes and invalidates offsets.
- `clearHighlights(rootEl)` unwraps every `.mdr-comment-hl` and calls
  `parent.normalize()` so later offsets stay stable.

- [ ] **Step 3: Syntax + regression check**

Run: `node --check src/demo_server/static/comments.js && node --test tests/js/`
Expected: exit 0, 6 passing.

- [ ] **Step 4: Commit**

```bash
git add src/demo_server/static/comments.js
git commit -m "feat: add comment storage and highlight rendering"
```

### Task D3: Panel UI, selection flow, To-tab

**Files:**
- Modify: `src/demo_server/static/comments.js`

- [ ] **Step 1: Bootstrap against the rail**

At the bottom of the file, outside the factory:

```js
(function () {
  if (typeof window === "undefined" || !window.MdrRail) return;
  window.MdrRail.ready(function () {
    window.MdrComments.init(window.MdrRail);
  });
})();
```

`init(rail)` must be a no-op when `rail.contentEl()` is null.

- [ ] **Step 2: Implement the tool**

Register `{id:'comments', icon:'\uD83D\uDCAC', label:'Comments', order:30, type:'panel'}`.

`onOpen(body, actions)`:

- `actions` gets one button: `<button class="mdr-btn">\u29C9 To tab</button>` with
  `title="Open the comment JSON in a new tab"`.
- `body` lists every comment, newest first, as `.mdr-comment-item` containing
  `.mdr-comment-quote` (the anchored `exact`), `.mdr-comment-text`, and
  `.mdr-comment-actions` with Edit and Delete buttons. Orphans get `.is-orphan` plus the
  note "anchor not found on this page".
- Empty state:
  `<div class="mdr-empty">No comments yet. Select some text to add one.</div>`.
- If a pending selection exists, the panel opens with a focused `.mdr-textarea` plus
  Save/Cancel at the top.

Selection flow:

- On `mouseup` and `keyup` within `rail.contentEl()`: if the selection is non-empty,
  entirely inside the content element, and at least 3 characters, position a
  `.mdr-selection-btn` (💬) near the selection end using `getBoundingClientRect()` plus
  `window.scrollX/scrollY`. Otherwise remove the button.
- Clicking it captures the quote via `domPointToOffset` on both range boundaries (falling
  back to the flattened-text index lookup of `selection.toString()` when a boundary is
  not a text node), stores the pending selection, and opens the panel.
- Save → append the record, persist, re-render highlights and the list, clear pending.

Interactions:

- Click a `.mdr-comment-hl` → open the panel, scroll its list entry into view, add
  `.is-active` to both for 1.5s.
- Click a `.mdr-comment-item` → `scrollIntoView({block: 'center'})` on its highlight and
  flash it.
- Edit → swap the text into an inline `.mdr-textarea` with Save/Cancel; Save updates
  `text` and `updatedAt`.
- Delete → `window.confirm`, then remove the record, unwrap its highlight,
  `normalize()` the parent, persist, and re-render the list.

`To tab`:

```js
var payload = {
  version: 1,
  file: location.pathname,
  exportedAt: Math.floor(Date.now() / 1000),
  comments: comments,
};
var blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
var url = URL.createObjectURL(blob);
window.open(url, "_blank", "noopener");
setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
```

No download, no import — deliberately out of scope.

Source-mode coordination: on `mdr:source-shown`, remove the selection button and stop
handling selections; on `mdr:source-hidden`, refresh the list (the detached nodes return
with their highlight spans intact, so this is a refresh, not a re-anchor).

- [ ] **Step 3: Syntax + regression check**

Run: `node --check src/demo_server/static/comments.js && node --test tests/js/`
Expected: exit 0, 6 passing.

- [ ] **Step 4: Commit**

```bash
git add src/demo_server/static/comments.js
git commit -m "feat: add comments panel, selection flow, and to-tab export"
```

---

# Integration (run by the orchestrator after A–D land)

### Task I1: Full test suite

- [ ] `python -m pytest tests -q` — all pass, including
  `test_rendered_page_links_reader_assets` (remove any `xfail` marker added in A7).
- [ ] `node --test tests/js/` — all pass.
- [ ] `node --check src/demo_server/static/reader.js src/demo_server/static/comments.js`.
- [ ] Python 3.9 syntax check:
  `python -c "import ast;[ast.parse(open(f).read(),feature_version=(3,9)) for f in ['src/demo_server/server.py','src/demo_server/pages.py','src/demo_server/static_files.py','src/demo_server/markdown_render.py']];print('3.9 ok')"`

### Task I2: Live smoke test

- [ ] Check `cli.py` for the exact flags, then start the server on `~/DemoDocs` on a free
  port (e.g. 8765).
- [ ] `curl -s localhost:8765/__reader__/reader.css | head -3` → CSS, not 404.
- [ ] Open a `.md` page in agent-browser; screenshot at 1440px and 375px.
- [ ] Cycle all six skins and both themes across all three themes; confirm readable
  contrast and no hardcoded color leaking through.
- [ ] Add, edit, delete a comment; reload and confirm the highlight re-anchors.
- [ ] Toggle source and back; confirm comments survive.
- [ ] Confirm the login page renders correctly at 375px in light and dark.

### Task I3: Docs + PR

- [ ] Update `README.md` and `CLAUDE.md`: `pages.py` / `static_files.py` / `static/` in
  the Layout section, the `?raw=1` parameter, and the skin/comment features.
- [ ] `gh pr create --base master`, linking the spec.

---

## Notes for parallel execution

- A, B, C, D touch disjoint file sets and may run simultaneously.
- A7's template-output test stays red until B lands — expected and documented.
- Nobody may edit a file outside their workstream's row in the File Structure table. A
  workstream that believes it needs a contract change must stop and report rather than
  edit another workstream's file.
