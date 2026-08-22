# demo-server

Static module server with optional passcode protection.

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Start the server (runs in foreground, Ctrl+C to stop)
demo-server start [-p 5566] [--public] path/to/modules/
```

## Running as a Service

Use `demo-server daemon` to manage demo-server with launchd (macOS) or systemd (Linux).

### macOS (launchd)

1. Edit `examples/com.demo-server.plist` — set the path to `demo-server` and your modules directory.
2. Install and start:

```bash
demo-server daemon install --config examples/com.demo-server.plist
demo-server daemon status
demo-server daemon logs
```

### Linux (systemd)

1. Edit `examples/demo-server.service` — set the `ExecStart` path.
2. Install and start:

```bash
demo-server daemon install --config examples/demo-server.service
demo-server daemon status
demo-server daemon logs
```

### Uninstall

```bash
demo-server daemon uninstall
```

## Module Structure

Each subdirectory under the served path is a "module" accessible at `/<module>/`:

```
modules/
├── project-a/
│   ├── index.html
│   └── style.css
└── project-b/
    ├── index.html
    └── .encrypt        <- passcode gate
```

## Configuration (`.config`)

An optional `.config` JSON file at the root of the served path controls the
listing page and redirects:

```json
{
  "pinned-modules": ["project-a"],
  "ignore-modules": ["scratch"],
  "redirect-modules": [
    {
      "slug": "old-tutorial",
      "redirect-to": "https://example.github.io/old-tutorial/",
      "description": "archived pages",
      "seconds": 5
    }
  ]
}
```

- `pinned-modules` — shown first, starred, on the `/all/` listing.
- `ignore-modules` — hidden from the `/all/` listing (direct URLs still work).
- `redirect-modules` — any request to `/<slug>` (or any path beneath it) renders
  a front-end "page moved" notice with a countdown, then redirects to
  `redirect-to`. Fires whether or not a folder named `<slug>` exists, and takes
  precedence over serving local files. `seconds` (default 5) sets the countdown;
  `description` is shown on the notice. The notice card is in
  `src/demo_server/assets/redirect-cat.svg`.

## Passcode Protection

```bash
demo-server set-passcode modules/project-b/
```

Visitors to that module will see a passcode form. After entering the correct
passcode they receive a signed cookie and can browse freely.

The cookie lasts 24 hours. When it expires mid-session, the passcode form
remembers the page that was requested (including its query string) and returns
there after a successful unlock instead of dropping the reader at the module
root. Redirect targets are validated server-side — only same-origin paths that
stay inside the module are accepted.

Hidden files (any path component starting with `.`) are never served (403).

## Markdown Reader

Markdown files are rendered server-side using the theme named in their
frontmatter (`theme: meridian-lite | github | minimal`; default
`meridian-lite`). Every rendered page gets a reader rail on the right edge:

| Button | What it does |
|---|---|
| 🌓 | Toggle light / dark |
| ⚙ | Settings: pick a **skin** (Theme default, GitHub, Solarized, Dracula, Nord, Sepia) |
| 💬 | Comments: select text to annotate it; edit, delete, or `⧉ To tab` the JSON |
| `</>` | Show the raw Markdown source |

**theme vs skin.** The *theme* is server-side and decides layout, typography
and structure. The *skin* is client-side and only swaps the color palette. All
three themes consume the same CSS variable contract, so any skin works on any
theme. Preferences (theme + skin) live in `localStorage` under `mdr-ui` and
apply site-wide.

Comments are stored per page in `localStorage` under
`mdr-comments:<path>`. They are anchored with a W3C TextQuoteSelector
(exact text plus 32-character prefix/suffix), so they survive edits elsewhere
in the document; an anchor that can no longer be found is listed as "orphaned"
rather than discarded. Comments never leave the browser — there is no server
storage, no download, and no import.

Appending `?raw=1` to a `.md` URL returns the original file as `text/plain`.
The passcode check runs first, so this is not a way around a protected module.

Reader assets are served from `/__reader__/` (an allowlist of `reader.css`,
`reader.js`, `comments.js`) with a one-year immutable cache. The `?v=` token is
a digest of the asset bytes, so a restart after any edit invalidates the cache
automatically — no version bump needed.

## Troubleshooting

If the server is running but not reachable from other machines, check firewall
rules:

```bash
# Allow traffic on port 5566
sudo iptables -I INPUT -p tcp --dport 5566 -j ACCEPT
```

Logs are written to `~/.demo-server/logs/server.log` when running as a service.
