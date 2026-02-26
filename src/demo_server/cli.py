import os
import socket
from pathlib import Path

import click

from demo_server.daemon import PID_FILE, daemon_status, daemonize, ensure_dirs, stop_daemon


@click.group()
def cli():
    """Static module server with optional passcode protection."""


@cli.command()
@click.option("-p", "--port", default=5566, type=int, help="Port to listen on.")
@click.option("--public", is_flag=True, help="Bind to all interfaces (0.0.0.0) instead of localhost.")
@click.argument("path", type=click.Path(exists=True))
def start(port: int, public: bool, path: str):
    """Start the demo server as a daemon."""
    import uvicorn
    from demo_server.server import create_app

    host = "0.0.0.0" if public else "127.0.0.1"
    path = str(Path(path).resolve())
    ensure_dirs()

    hostname = socket.gethostname()
    click.echo(f"Starting demo-server on http://{hostname}:{port}")
    click.echo(f"  Serving: {path}")
    click.echo(f"  Bind:    {host}")
    click.echo(f"  Logs:    ~/.demo-server/logs/server.log")
    click.echo(f"  PID:     ~/.demo-server/daemon.pid")

    daemonize()

    app = create_app(path)
    uvicorn.run(app, host=host, port=port, log_level="info")


@cli.command()
def stop():
    """Stop the running demo server."""
    stop_daemon()


@cli.command()
@click.option("-p", "--port", default=5566, type=int, help="Port to listen on.")
@click.option("--public", is_flag=True, help="Bind to all interfaces (0.0.0.0) instead of localhost.")
@click.argument("path", type=click.Path(exists=True))
def restart(port: int, public: bool, path: str):
    """Restart the demo server."""
    pid, running = daemon_status()
    if running:
        stop_daemon()
        # Wait briefly for the port to be released
        import time
        time.sleep(0.5)
    elif pid is not None:
        PID_FILE.unlink(missing_ok=True)

    ctx = click.Context(start, info_name="start")
    ctx.params = {"port": port, "public": public, "path": path}
    start.invoke(ctx)


@cli.command()
def status():
    """Show whether the demo server is running."""
    pid, running = daemon_status()
    if pid is None:
        click.echo("Not running (no PID file)")
    elif running:
        click.echo(f"Running (PID {pid})")
    else:
        click.echo(f"Not running (stale PID file for {pid})")
        PID_FILE.unlink(missing_ok=True)


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
