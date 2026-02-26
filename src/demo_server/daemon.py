from __future__ import annotations

import os
import sys
import signal
from pathlib import Path
from typing import Optional, Tuple

BASE_DIR = Path.home() / ".demo-server"
PID_FILE = BASE_DIR / "daemon.pid"
LOG_FILE = BASE_DIR / "logs" / "server.log"


def ensure_dirs():
    (BASE_DIR / "logs").mkdir(parents=True, exist_ok=True)


def daemonize(pid_file: Path = PID_FILE, log_file: Path = LOG_FILE):
    # First fork
    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    os.setsid()

    # Second fork
    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    # Redirect stdout/stderr to log file
    sys.stdout.flush()
    sys.stderr.flush()

    log_fd = open(log_file, "a")
    os.dup2(log_fd.fileno(), sys.stdout.fileno())
    os.dup2(log_fd.fileno(), sys.stderr.fileno())

    # Write PID file
    pid_file.write_text(str(os.getpid()))


def daemon_status(pid_file: Path = PID_FILE) -> Tuple[Optional[int], bool]:
    """Return (pid, running). pid is None if no PID file exists."""
    if not pid_file.exists():
        return None, False
    pid = int(pid_file.read_text().strip())
    try:
        os.kill(pid, 0)  # signal 0 = existence check
        return pid, True
    except ProcessLookupError:
        return pid, False
    except PermissionError:
        return pid, True  # process exists but owned by another user


def stop_daemon(pid_file: Path = PID_FILE):
    if not pid_file.exists():
        print("No PID file found — daemon not running?")
        return

    pid = int(pid_file.read_text().strip())
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"Sent SIGTERM to PID {pid}")
    except ProcessLookupError:
        print(f"Process {pid} not found — stale PID file")
    finally:
        pid_file.unlink(missing_ok=True)
