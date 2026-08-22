# Reader Enhancements — Design

Date: 2026-08-22
Branch: `feat/reader-enhancements`

Three independent features for demo-server:

1. Preserve the requested URL across passcode login.
2. Redesign the passcode page: responsive, dark-mode aware, Meridian-styled.
3. Add a right-side reader rail to Markdown pages: skin settings, comments, source toggle.

## Current State

- `server.py` (485 lines) holds routing, auth, and three inline HTML page constants
  (`PASSCODE_FORM`, `WELCOME_PAGE`, `REDIRECT_PAGE`).
- Auth is a signed cookie (`auth_{module}`, `auth___root__`) with a 24-hour token
  lifetime. When the token is missing or expired, `serve()` returns the passcode form
  at the requested URL with status 401. `POST /{module}/__auth__` always redirects to
  `/{module}/`, so any deeper path is lost.
- `markdown_render.py` renders `.md` files through one of three Jinja2 templates in
  `themes/`. Only `meridian-lite` uses CSS custom properties and ships a dark face,
  a fixed TOC, and a 🌓 toggle. `github` and `minimal` hardcode colors, have no dark
  mode, and never render `{{ toc }}`.
- `chrome-swiss-knife/markdown-reader` (a Chrome extension, separate repo) already
  implements skins and comments; its pure logic is the reference implementation to
  port from.

## Vocabulary

- **theme** — server-side: which Jinja2 template renders the page. Chosen in
  frontmatter (`theme: meridian-lite`). Controls layout, typography, structure.
- **skin** — client-side: which color palette is applied. Chosen by the reader in the
  settings panel, persisted in `localStorage`. Controls colors only.

These are orthogonal. A `github` *theme* page can be shown in the `dracula` *skin*.

## Feature 1 — Login Redirect Preservation

**Goal:** After the session expires, logging in returns the reader to the exact page
they asked for, not the module root.

**Mechanism**

- The passcode form gains a hidden `next` field.
- `serve()` populates it with the current request path plus query string
  (`request.url.path` + `?` + `request.url.query`).
- `listing()` (`/all/`) populates it with `/all/`.
- `POST /{module}/__auth__` accepts `next: str = Form("")` and redirects there on
  success instead of `/{module}/`.
- A wrong passcode re-renders the form with `next` preserved.

**Validation — `safe_next(candidate, module)`**

Returns the candidate only if all hold, else falls back to `/{module}/`:

1. Non-empty and starts with a single `/` (rejects absolute URLs and
   protocol-relative `//evil.com`).
2. Contains no backslash (rejects `/\evil.com`, which some browsers normalize).
3. `posixpath.normpath` of the path component still starts with `/{module}/` — or
   equals `/{module}` — so a `../` escape cannot leave the module. For the root form
   the required prefix is `/all/`.

Query strings and fragments beyond the path are preserved but never influence the
prefix check; the check runs on the path component only.

**Tests**

- Deep path `/mod/sub/page.html` → form carries that `next` → POST redirects there.
- `next=https://evil.com`, `//evil.com`, `/other-module/`, `/mod/../../etc` all fall
  back to `/mod/`.
- Empty/absent `next` falls back to `/mod/`.
- Wrong passcode keeps `next` in the re-rendered form.

## Feature 2 — Responsive Login Page

**Goal:** The passcode page should look like the rest of the site and work on a phone.

**Refactor:** Move `PASSCODE_FORM`, `WELCOME_PAGE`, and `REDIRECT_PAGE` (plus
`_render_redirect` and `_redirect_cat_svg`) out of `server.py` into
`src/demo_server/pages.py`. `server.py` keeps routing, auth, and listing logic.
`pages.py` exposes `render_passcode_page(module, next_url, error="")` and
`render_welcome_page(count, modules_html)`; the redirect renderer moves as-is.

**Design**

- Centered card, `max-width: 380px`, `width: 100%`, fluid padding — same visual family
  as the `/all/` panel and the redirect page.
- Dark face via `@media (prefers-color-scheme: dark)`, matching the redirect page
  variables.
- `input { font-size: 16px }` so iOS Safari does not zoom on focus.
- Full-width submit button below ~420px.
- Semantic markup: `<label>` for the passcode input, `aria-live="polite"` on the error
  region, `autocomplete="current-password"`, `autofocus`.
- `next` rendered as a hidden input, HTML-escaped with `quote=True`.

The rate-limit (429) and generic error responses stay plain — out of scope.

## Feature 3 — Reader Rail

Applies to Markdown-rendered pages only. Static HTML files are still served untouched
by `FileResponse`.

### 3.0 Shared assets

New directory `src/demo_server/static/` with `reader.css` and `reader.js`.

New route registered **before** the `/{module}/{path:path}` catch-all:

```
GET /__reader__/{filename}
```

- Serves only from a hardcoded allowlist (`reader.css`, `reader.js`) — no path
  traversal surface.
- `Cache-Control: public, max-age=31536000, immutable`; templates request
  `?v={version}` where version is the package version from
  `importlib.metadata.version("demo-server")`, falling back to a build constant.
- No auth: the assets contain no user content.

All three templates load these assets and render a common rail mount point.

### 3.1 Variable contract + skins

`reader.css` defines the palette contract that every theme consumes:

```
--bg --surface --text --text-sec --text-muted
--primary --primary-hover --primary-light
--accent --accent-light --warn --warn-light --danger
--border --border-strong --shadow --shadow-md
```

- `meridian-lite` already defines these; its declarations stay in the template as the
  default face.
- `github` and `minimal` are variabilized: their existing hardcoded colors become
  `:root` variable values (their default light face), and each gains a `[data-theme="dark"]`
  block. No layout or typography changes beyond swapping literal colors for `var(...)`.
- Skins live in `reader.css` as `html[data-skin="X"]` (light face) and
  `html[data-skin="X"][data-theme="dark"]` (dark face), overriding only variables.
  Ported skins: `github`, `solarized`, `dracula`, `nord`, `sepia`. The absence of
  `data-skin` (or `data-skin="default"`) means "use the theme's own palette".
- Skin selectors must beat the template's own `:root` rules. Since the template's
  `<style>` is inline in `<head>` and `reader.css` is a `<link>`, load order alone is
  not reliable — skins therefore use the higher-specificity `html[data-skin=...]`
  selector (0,1,1) which outranks `:root` (0,1,0) regardless of order.

### 3.2 Rail and panels

Right edge, `position: fixed`, vertical stack of icon buttons, replacing the current
lone 🌓 button:

| Button | Panel |
|---|---|
| 🌓 | no panel — toggles `data-theme` directly (existing behavior preserved) |
| ⚙ | Settings: skin picker |
| 💬 | Comments: list + actions |
| `</>` | no panel — toggles source view |

- Panels slide in from the right, `width: 320px`, full height, above content.
- Below 640px they become a bottom sheet at `height: 70vh`, full width.
- One panel open at a time; Esc closes; clicking the active rail button toggles.
- Buttons carry `aria-label`, `aria-expanded`, and `aria-controls`.
- The rail sits above the TOC (`z-index` above `.toc`'s 40) and must not overlap the
  prose column at any width.

### 3.3 Settings panel

- Skin picker: `default` plus the five ported skins, rendered as a radio list with a
  small color swatch each.
- Light/dark toggle mirrored here as well as on the rail.
- Persistence: one global key, `localStorage["mdr-ui"]`, JSON `{ theme, skin }`.
  Applied by an inline bootstrap snippet in each template `<head>` (before paint, to
  avoid a flash), then re-read by `reader.js`.
- The existing `localStorage["theme"]` key is migrated into `mdr-ui` on first read and
  then ignored.

### 3.4 Comments panel

Ported from `markdown-reader/src/comments.js`. The pure anchoring functions
(`captureQuote`, `affixScore`, `resolveQuote`, `buildTextIndex`, `domPointToOffset`,
range wrapping) are copied with attribution; the Chrome-extension storage layer is
replaced with `localStorage`.

**Anchoring:** W3C TextQuoteSelector — `{ exact, prefix, suffix }` with 32-character
affixes. On load, each comment resolves against the flattened text of `.md-container`;
ties broken by affix score. Unresolvable comments are kept in storage and listed in
the panel as "orphaned" rather than silently dropped.

**Interaction**

- Selecting text inside `.md-container` shows a floating 💬 button near the selection.
- Clicking it opens the panel with a new-comment textarea pre-anchored to the
  selection.
- Saving wraps the range in `<span class="mdr-comment-hl" data-id="...">` and adds the
  comment to the panel list.
- Clicking a list entry scrolls to and flashes its highlight; clicking a highlight
  focuses the list entry.
- Each entry has Edit and Delete. Delete unwraps the highlight span and re-normalizes
  the parent so neighboring offsets stay stable.
- `⧉ To tab` opens `{ version: 1, file, exportedAt, comments }` as pretty JSON in a
  new tab via a `blob:` URL. No file download, no import — explicitly out of scope.

**Storage:** `localStorage["mdr-comments:" + location.pathname]`, an array of
`{ id, quote: {exact, prefix, suffix}, text, createdAt, updatedAt }`. IDs are
`c_<base36 time><random>`.

### 3.5 Source toggle

**Server:** `GET /{module}/{path}` gains a `raw` query parameter. When `raw` is truthy
and the resolved file has a `.md` suffix, return `PlainTextResponse` with
`text/plain; charset=utf-8` instead of rendering. The passcode check, hidden-file
check, and path-traversal check all run first and unchanged — `raw` never bypasses
auth. Non-`.md` files ignore `raw`.

**Client:** The `</>`  button fetches `location.pathname + "?raw=1"` once, caches the
text, and swaps `.md-container` for a `<pre class="mdr-source">` (the rendered DOM is
detached and kept, not destroyed, so comments survive the round trip). The TOC is
hidden in source mode. Toggling back restores the original DOM with no reload. A
failed fetch shows an inline error in the panel area and leaves the rendered view up.

## Verification

Run `demo-server` against `~/DemoDocs` (16 Markdown files, 8000 port free) and check:

- **F1:** `curl -i` a deep path in an encrypted module → 401 with the right `next`;
  POST with correct passcode → 303 to that path; POST with each hostile `next` → 303
  to `/{module}/`.
- **F2:** Screenshot the login page at 375px and 1440px, light and dark.
- **F3:** Screenshot each of the three themes with each skin; create, edit, delete a
  comment and reload to confirm re-anchoring; open `⧉ To tab`; toggle source and back;
  confirm `?raw=1` on an encrypted module without a cookie returns 401, not source.

Automated tests cover `safe_next` and the `raw` route; the rest is manual browser
verification.

## Out of Scope

- Injecting the rail into static HTML pages.
- Comment import, file download export, or any server-side comment storage.
- Sharing or syncing comments between browsers.
- Changing the cookie lifetime or the auth mechanism itself.
