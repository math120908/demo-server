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

Hidden files (any path component starting with `.`) are never served (403).

## Troubleshooting

If the server is running but not reachable from other machines, check firewall
rules:

```bash
# Allow traffic on port 5566
sudo iptables -I INPUT -p tcp --dport 5566 -j ACCEPT
```

Logs are written to `~/.demo-server/logs/server.log` when running as a service.
