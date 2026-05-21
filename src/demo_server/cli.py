import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import click

SERVICE_LABEL = "com.demo-server.app"
SYSTEMD_UNIT = "demo-server.service"
LOG_DIR = Path.home() / ".demo-server" / "logs"
LOG_FILE = LOG_DIR / "server.log"


@click.group()
def cli():
    """Static module server with optional passcode protection."""


@cli.command()
@click.option("-p", "--port", default=5566, type=int, help="Port to listen on.")
@click.option("--public", is_flag=True, help="Bind to all interfaces (0.0.0.0) instead of localhost.")
@click.argument("path", type=click.Path(exists=True))
def start(port: int, public: bool, path: str):
    """Start the demo server in the foreground."""
    import uvicorn
    from demo_server.server import create_app

    host = "0.0.0.0" if public else "127.0.0.1"
    path = str(Path(path).resolve())

    hostname = socket.gethostname()
    click.echo(f"Starting demo-server on http://{hostname}:{port}")
    click.echo(f"  Serving: {path}")
    click.echo(f"  Bind:    {host}")

    app = create_app(path)
    uvicorn.run(app, host=host, port=port, log_level="info")


@cli.command("set-passcode")
@click.argument("module_path", type=click.Path(exists=True))
@click.option("--passcode", prompt=True, hide_input=True, confirmation_prompt=True)
def set_passcode(module_path: str, passcode: str):
    """Set a hashed passcode for a module directory."""
    from demo_server.server import hash_passcode

    module_dir = Path(module_path).resolve()
    if not module_dir.is_dir():
        click.echo("Error: path must be a directory", err=True)
        raise SystemExit(1)

    encrypt_file = module_dir / ".encrypt"
    encrypt_file.write_text(hash_passcode(passcode))
    os.chmod(encrypt_file, 0o600)
    click.echo(f"Passcode set for {module_dir.name}")


# ---------------------------------------------------------------------------
# daemon subcommand group
# ---------------------------------------------------------------------------


@cli.group()
def daemon():
    """Manage demo-server as a system service (launchd / systemd)."""


def _is_macos() -> bool:
    return sys.platform == "darwin"


@daemon.command()
@click.option(
    "-c",
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True),
    help="Path to a launchd plist (macOS) or systemd unit file (Linux).",
)
def install(config_path: str):
    """Install and start the demo-server service."""
    src = Path(config_path).resolve()

    if _is_macos():
        dest_dir = Path.home() / "Library" / "LaunchAgents"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f"{SERVICE_LABEL}.plist"
        shutil.copy2(src, dest)
        click.echo(f"Copied {src.name} -> {dest}")
        subprocess.run(["launchctl", "load", str(dest)], check=True)
        subprocess.run(["launchctl", "start", SERVICE_LABEL], check=True)
        click.echo(f"Service '{SERVICE_LABEL}' loaded and started.")
    else:
        dest_dir = Path.home() / ".config" / "systemd" / "user"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / SYSTEMD_UNIT
        shutil.copy2(src, dest)
        click.echo(f"Copied {src.name} -> {dest}")
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
        subprocess.run(
            ["systemctl", "--user", "enable", "--now", SYSTEMD_UNIT],
            check=True,
        )
        click.echo(f"Service '{SYSTEMD_UNIT}' enabled and started.")


@daemon.command()
def uninstall():
    """Stop and remove the demo-server service."""
    if _is_macos():
        dest = Path.home() / "Library" / "LaunchAgents" / f"{SERVICE_LABEL}.plist"
        subprocess.run(["launchctl", "stop", SERVICE_LABEL])
        subprocess.run(["launchctl", "unload", str(dest)])
        dest.unlink(missing_ok=True)
        click.echo(f"Service '{SERVICE_LABEL}' stopped and removed.")
    else:
        dest = Path.home() / ".config" / "systemd" / "user" / SYSTEMD_UNIT
        subprocess.run(["systemctl", "--user", "disable", "--now", SYSTEMD_UNIT])
        dest.unlink(missing_ok=True)
        subprocess.run(["systemctl", "--user", "daemon-reload"])
        click.echo(f"Service '{SYSTEMD_UNIT}' disabled and removed.")


@daemon.command()
def status():
    """Show whether the demo-server service is running."""
    if _is_macos():
        click.echo("Platform: macOS (launchd)")
        click.echo(f"Service:  {SERVICE_LABEL}")
        result = subprocess.run(
            ["launchctl", "list"],
            capture_output=True,
            text=True,
        )
        for line in result.stdout.splitlines():
            if "demo-server" in line:
                parts = line.split()
                pid = parts[0] if parts[0] != "-" else None
                click.echo(f"State:    running (PID {pid})" if pid else "State:    not running")
                return
        click.echo("State:    not installed")
    else:
        click.echo("Platform: Linux (systemd)")
        click.echo(f"Service:  {SYSTEMD_UNIT}")
        result = subprocess.run(
            ["systemctl", "--user", "is-active", SYSTEMD_UNIT],
            capture_output=True,
            text=True,
        )
        state = result.stdout.strip()
        click.echo(f"State:    {state}")


@daemon.command()
def logs():
    """Tail the demo-server log file."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    if not LOG_FILE.exists():
        click.echo(f"No log file yet at {LOG_FILE}")
        raise SystemExit(1)
    click.echo(f"Tailing {LOG_FILE}  (Ctrl+C to stop)")
    try:
        subprocess.run(["tail", "-f", str(LOG_FILE)])
    except KeyboardInterrupt:
        pass
