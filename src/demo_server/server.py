from __future__ import annotations

import hashlib
import html
import json
import logging
import os
import posixpath
import secrets
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, Form
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
)
from itsdangerous import URLSafeTimedSerializer

from demo_server import pages, static_files

logger = logging.getLogger(__name__)

BASE_DIR = Path.home() / ".demo-server"
SECRET_FILE = BASE_DIR / ".secret"

AUTH_COOKIE_MAX_AGE = 86400  # 24 hours


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


def _request_target(request: Request) -> str:
    """The path (plus query) the reader actually asked for."""
    target = request.url.path
    if request.url.query:
        target = target + "?" + request.url.query
    return target


def _get_secret() -> str:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text().strip()
    secret = secrets.token_hex(32)
    SECRET_FILE.write_text(secret)
    os.chmod(SECRET_FILE, 0o600)
    return secret


def hash_passcode(passcode: str) -> str:
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", passcode.encode(), salt, 100_000)
    return salt.hex() + ":" + h.hex()


def verify_passcode(passcode: str, stored: str) -> bool:
    if ":" not in stored:
        # Legacy plaintext — still compare safely
        return secrets.compare_digest(passcode, stored)
    salt_hex, hash_hex = stored.split(":", 1)
    salt = bytes.fromhex(salt_hex)
    h = hashlib.pbkdf2_hmac("sha256", passcode.encode(), salt, 100_000)
    return secrets.compare_digest(h.hex(), hash_hex)


class RateLimiter:
    def __init__(self, max_attempts: int = 5, window: int = 60):
        self.max_attempts = max_attempts
        self.window = window
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def is_limited(self, key: str) -> bool:
        now = time.time()
        self._attempts[key] = [
            t for t in self._attempts[key] if now - t < self.window
        ]
        if len(self._attempts[key]) >= self.max_attempts:
            return True
        self._attempts[key].append(now)
        return False


def _load_config(base: Path) -> dict:
    config_file = base / ".config"
    if not config_file.exists():
        return {}
    try:
        data = json.loads(config_file.read_text())
        if not isinstance(data, dict):
            return {}
        for key in ("pinned-modules", "ignore-modules"):
            if key in data and not isinstance(data[key], list):
                data.pop(key)
            elif key in data:
                data[key] = [m for m in data[key] if isinstance(m, str)]
        if "redirect-modules" in data:
            rm = data["redirect-modules"]
            if not isinstance(rm, list):
                data.pop("redirect-modules")
            else:
                data["redirect-modules"] = [
                    x for x in rm
                    if isinstance(x, dict)
                    and isinstance(x.get("slug"), str)
                    and isinstance(x.get("redirect-to"), str)
                ]
        return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read .config: %s", exc)
        return {}


def _match_redirect(config: dict, module: str) -> dict | None:
    for item in config.get("redirect-modules", []):
        if item.get("slug") == module:
            return item
    return None


RECENT_WINDOW = 30 * 86400  # modules updated within 30 days count as "Recent"


def _module_mtime(module_dir: Path) -> float:
    """Update time of a module = the module directory's own mtime.

    We intentionally use the directory's mtime rather than the newest file
    inside it. Bulk operations (rdev sync, restore-from-backup) re-touch every
    file's mtime, which would collapse every module's "newest file" to the same
    sync timestamp and destroy the chronological ordering. A directory's own
    mtime only changes when entries are added/removed/renamed in it, which
    tracks "when this demo was last published" far more reliably.

    Note: editing a file's *contents* in place does not change the directory
    mtime. To bump a module to the top after such an edit, touch the directory
    (`touch <module_dir>`).
    """
    try:
        return module_dir.stat().st_mtime
    except OSError:
        return 0.0


def _format_when(mtime: float, now: float, recent: bool) -> str:
    """Recent modules show a relative time; older ones an absolute date."""
    if recent:
        days = int((now - mtime) // 86400)
        if days <= 0:
            return "today"
        if days == 1:
            return "1 day ago"
        return f"{days} days ago"
    dt = datetime.fromtimestamp(mtime)
    if dt.year == datetime.fromtimestamp(now).year:
        return dt.strftime("%b %-d")
    return dt.strftime("%b %-d, %Y")


def _render_section(label: str, entries: list, now: float, *, recent: bool, pinned: bool) -> str:
    """Render one section (Pinned / Recent / Earlier) as a header + rows."""
    if not entries:
        return ""
    count = "" if pinned else f'<span class="count">{len(entries)}</span>'
    html_parts = [f'<div class="sec-label">{label}{count}</div>']
    for name, mtime in entries:
        when = _format_when(mtime, now, recent)
        classes = "row"
        if pinned:
            classes += " pin"
        elif when == "today":
            classes += " fresh"
        safe = html.escape(name)
        html_parts.append(
            f'<a class="{classes}" href="/{safe}/">'
            f'<span class="name">{safe}</span>'
            f'<span class="when">{when}</span></a>'
        )
    return "".join(html_parts)


def create_app(base_path: str) -> FastAPI:
    base = Path(base_path).resolve()
    secret = _get_secret()
    serializer = URLSafeTimedSerializer(secret)
    limiter = RateLimiter()
    app = FastAPI()

    @app.get("/", response_class=HTMLResponse)
    async def home():
        return ""

    @app.post("/all/__auth__")
    async def root_auth(
        request: Request,
        passcode: str = Form(...),
        next: str = Form(""),
    ):
        encrypt_file = base / ".encrypt"
        if not encrypt_file.exists():
            return HTMLResponse("Not found", status_code=404)

        client_ip = request.client.host if request.client else "unknown"
        if limiter.is_limited(f"{client_ip}:__root__"):
            return HTMLResponse("Too many attempts. Try again later.", status_code=429)

        stored = encrypt_file.read_text().strip()
        if not verify_passcode(passcode, stored):
            html = pages.render_passcode_page(
                "all", safe_next(next, "__root__"), "Wrong passcode."
            )
            return HTMLResponse(html, status_code=403)

        response = RedirectResponse(safe_next(next, "__root__"), status_code=303)
        token = serializer.dumps("__root__")
        response.set_cookie(
            "auth___root__", token, httponly=True, samesite="lax",
        )
        return response

    @app.get("/all/", response_class=HTMLResponse)
    async def listing(request: Request):
        # Root-level encrypt check
        encrypt_file = base / ".encrypt"
        if encrypt_file.exists():
            cookie = request.cookies.get("auth___root__")
            try:
                value = serializer.loads(cookie, max_age=AUTH_COOKIE_MAX_AGE) if cookie else None
            except Exception:
                value = None
            if value != "__root__":
                html = pages.render_passcode_page("all", "/all/")
                return HTMLResponse(html, status_code=401)

        config = _load_config(base)
        pinned_cfg = config.get("pinned-modules", [])
        pinned = set(pinned_cfg)
        ignored = set(config.get("ignore-modules", []))

        now = time.time()
        mtimes = {
            e.name: _module_mtime(e)
            for e in base.iterdir()
            if e.is_dir() and not e.name.startswith(".") and e.name not in ignored
        }

        # Primary: mtime desc. Tiebreaker: name asc.
        ordered = sorted(mtimes.items(), key=lambda kv: (-kv[1], kv[0]))

        pinned_list = [(n, mtimes[n]) for n in pinned_cfg if n in mtimes]
        rest = [(n, m) for n, m in ordered if n not in pinned]
        recent = [(n, m) for n, m in rest if now - m < RECENT_WINDOW]
        earlier = [(n, m) for n, m in rest if now - m >= RECENT_WINDOW]

        modules_html = (
            _render_section("Pinned", pinned_list, now, recent=False, pinned=True)
            + _render_section("Recent · past month", recent, now, recent=True, pinned=False)
            + _render_section("Earlier", earlier, now, recent=False, pinned=False)
        )

        return pages.render_welcome_page(len(mtimes), modules_html)

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

    @app.post("/{module}/__auth__")
    async def auth(
        module: str,
        request: Request,
        passcode: str = Form(...),
        next: str = Form(""),
    ):
        module_dir = base / module
        encrypt_file = module_dir / ".encrypt"
        if not module_dir.is_dir() or not encrypt_file.exists():
            return HTMLResponse("Not found", status_code=404)

        client_ip = request.client.host if request.client else "unknown"
        if limiter.is_limited(f"{client_ip}:{module}"):
            return HTMLResponse("Too many attempts. Try again later.", status_code=429)

        stored = encrypt_file.read_text().strip()
        if not verify_passcode(passcode, stored):
            return HTMLResponse(
                pages.render_passcode_page(
                    module, safe_next(next, module), "Wrong passcode."
                ),
                status_code=403,
            )

        response = RedirectResponse(safe_next(next, module), status_code=303)
        token = serializer.dumps(module)
        response.set_cookie(
            f"auth_{module}", token, httponly=True, samesite="lax",
        )
        return response

    @app.get("/{module}/{path:path}")
    async def serve(module: str, request: Request, path: str = ""):
        # Front-end redirect for migrated modules — fires whether or not the
        # folder exists, for the slug itself and any path beneath it.
        redirect = _match_redirect(_load_config(base), module)
        if redirect:
            return HTMLResponse(
                pages.render_redirect(
                    slug=module,
                    target=redirect["redirect-to"],
                    description=redirect.get("description", ""),
                    seconds=redirect.get("seconds", 5),
                )
            )

        module_dir = base / module
        if not module_dir.is_dir():
            return HTMLResponse("Not found", status_code=404)

        # `ignore-modules` only hides from the /all/ listing; direct URL access is allowed.

        if not path or path.endswith("/"):
            html_index = module_dir / (path + "index.html")
            md_index = module_dir / (path + "index.md")
            if html_index.is_file():
                path = path + "index.html"
            elif md_index.is_file():
                path = path + "index.md"
            else:
                path = path + "index.html"  # fall through to 404

        # Hidden file check
        for part in Path(path).parts:
            if part.startswith("."):
                return HTMLResponse("Forbidden", status_code=403)
        if module.startswith("."):
            return HTMLResponse("Forbidden", status_code=403)

        # Encrypt check
        encrypt_file = module_dir / ".encrypt"
        if encrypt_file.exists():
            cookie = request.cookies.get(f"auth_{module}")
            try:
                value = serializer.loads(cookie, max_age=AUTH_COOKIE_MAX_AGE) if cookie else None
            except Exception:
                value = None
            if value != module:
                return HTMLResponse(
                    pages.render_passcode_page(module, _request_target(request)),
                    status_code=401,
                )

        file_path = (module_dir / path).resolve()
        # Prevent path traversal — append os.sep to avoid prefix collisions
        if not str(file_path).startswith(str(module_dir) + os.sep):
            return HTMLResponse("Forbidden", status_code=403)

        if not file_path.is_file():
            return HTMLResponse("Not found", status_code=404)

        if file_path.suffix == ".md":
            if request.query_params.get("raw"):
                return PlainTextResponse(
                    file_path.read_text(encoding="utf-8"),
                    media_type="text/plain; charset=utf-8",
                )
            from demo_server.markdown_render import render_md_file

            html_content = render_md_file(file_path)
            return HTMLResponse(html_content)

        return FileResponse(file_path)

    return app
