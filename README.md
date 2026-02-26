# demo-server

Static module server with optional passcode protection.

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Start the server (daemonizes by default)
demo-server start [-p 5566] path/to/modules/

# Stop the server
demo-server stop
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
    └── .encrypt        ← passcode gate
```

## Passcode Protection

To protect a module, create a `.encrypt` file containing the passcode:

```bash
echo "my-secret" > modules/project-b/.encrypt
```

Visitors to that module will see a passcode form. After entering the correct
passcode they receive a signed cookie and can browse freely.

Hidden files (any path component starting with `.`) are never served (403).

## Troubleshooting

If the server is running but not reachable from other machines, check firewall
rules:

```bash
# List current rules
sudo iptables -L

# Allow traffic on port 5566
sudo iptables -I INPUT -p tcp --dport 5566 -j ACCEPT
```

Logs are written to `~/.demo-server/logs/server.log`.
