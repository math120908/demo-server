# demo-server

A small FastAPI app that serves static module directories (one folder per
"module") with optional passcode encryption, server-side Markdown rendering,
and a sorted `/all/` landing page.

## Python compatibility — target **>= 3.9**

The deploy host (`ckuo-ld2`) runs **Python 3.9**. Development machines often
run 3.12+, so 3.10-only syntax compiles and runs locally but **crashes on the
server at import time**. This has bitten us once already (`str | None` at module
scope → `TypeError` on 3.9).

Rules:

- `from __future__ import annotations` is enabled at the top of every module.
  Keep it. It defers annotations to strings so `X | Y` unions in signatures and
  variable annotations are never evaluated at runtime.
- For a union that is genuinely evaluated at runtime (not just an annotation —
  e.g. `isinstance`, `cast`, a Pydantic/FastAPI field that gets introspected),
  use `typing.Optional[T]` / `typing.Union[A, B]`, **not** `A | B`.
- Avoid other 3.10+ syntax: structural pattern matching (`match`/`case`),
  parenthesized context managers, etc.
- `list[...]`, `dict[...]`, `tuple[...]` builtins-as-generics are fine — those
  work from 3.9 (PEP 585).
- `requires-python = ">=3.9"` in `pyproject.toml` is the source of truth. Don't
  lower it.

Before deploying a change that touches imports or annotations, verify it starts
under 3.9 (run the entry point on `ckuo-ld2`, not just locally).

## Deployment (ckuo-ld2)

- systemd **user** service: `demo-server.service`
  (`~/.config/systemd/user/demo-server.service`).
- Installed **editable** into the host's 3.9 site-packages; the source tree is
  rdev-synced from local — a local commit lands on the host's checkout.
- Serves `~/DemoDocs` on port 8000 (`--public`). Host-specific setup lives in
  `~/DemoDocs/.ckuo-ld2/`.
- Restart after a code change: `systemctl --user restart demo-server`, then
  confirm `systemctl --user is-active demo-server` is `active` (a crash-loop
  shows `activating (auto-restart)`).

## Layout

- `src/demo_server/server.py` — FastAPI app, routing, auth, the `/all/` listing.
- `src/demo_server/pages.py` — standalone HTML pages (passcode, `/all/` welcome,
  move-redirect) and their renderers.
- `src/demo_server/cli.py` — `demo-server` CLI entry point.
- `src/demo_server/markdown_render.py` — Markdown → HTML rendering.
- `src/demo_server/static_files.py` — allowlist and cache-busting digest for the
  reader assets served at `/__reader__/`.
- `src/demo_server/static/` — `reader.css` (variable contract + skins + rail UI),
  `reader.js` (`window.MdrRail`, settings, source toggle), `comments.js`
  (anchoring + comments panel). Client-side only; no build step.
- `src/demo_server/themes/` — HTML templates per theme. All three consume the
  same CSS variable contract so any skin works on any theme.
- `tests/` — pytest suite; `tests/js/` runs under `node --test`.
- `docs/superpowers/specs/` — design docs for non-trivial changes.
- `docs/superpowers/plans/` — implementation plans.

## Reader conventions

- **theme** is server-side (which Jinja template renders the page, chosen in
  frontmatter). **skin** is client-side (which palette, chosen by the reader and
  stored in `localStorage['mdr-ui']`). Keep them orthogonal.
- Skins override only palette variables and are keyed on `html[data-skin="X"]`
  — specificity (0,1,1), which beats a template's `:root` (0,1,0) without
  needing `!important` or a particular load order.
- The DOM contract between the templates and the reader JS (`#mdr-rail`,
  `#mdr-panel`, `#mdr-content`, the `mdr-ui` bootstrap snippet) is shared by all
  three templates. Changing it means changing all three plus both JS files.
- Reader assets are cached `immutable` for a year; the `?v=` token is a digest
  of their bytes, so restarting the service after an edit is enough to
  invalidate it.

