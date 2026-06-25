import hashlib
import html
import json
import logging
import os
import secrets
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request, Form
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from itsdangerous import URLSafeTimedSerializer

logger = logging.getLogger(__name__)

BASE_DIR = Path.home() / ".demo-server"
SECRET_FILE = BASE_DIR / ".secret"

AUTH_COOKIE_MAX_AGE = 86400  # 24 hours


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


PASSCODE_FORM = """\
<!DOCTYPE html>
<html><head><title>Passcode Required</title>
<style>
  body {{ font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }}
  .box {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,.1); text-align: center; }}
  input[type=password] {{ padding: .5rem; font-size: 1rem; margin: .5rem 0; }}
  button {{ padding: .5rem 1.5rem; font-size: 1rem; cursor: pointer; }}
  .error {{ color: red; }}
</style></head>
<body><div class="box">
  <h2>🔒 {module}</h2>
  <form method="post" action="/{module}/__auth__">
    <div><input type="password" name="passcode" placeholder="Enter passcode" autofocus /></div>
    {error}
    <div><button type="submit">Submit</button></div>
  </form>
</div></body></html>
"""

WELCOME_PAGE = """\
<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>demo-server</title>
<style>
  :root {{ --ink: #1f2430; --muted: #8a93a3; --line: #eceef2;
    --star: #f59e0b; --bg: #f0f2f5; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    min-height: 100vh; background: var(--bg); color: var(--ink);
    display: flex; justify-content: center; padding: 3rem 1rem; }}
  .panel {{ background: #fff; border: 1px solid var(--line); border-radius: 14px;
    box-shadow: 0 4px 24px rgba(20,30,60,.06); max-width: 600px; width: 100%;
    height: fit-content; padding: 1.6rem 1.7rem; }}
  .title {{ font-size: 1.5rem; font-weight: 750; }}
  .tagline {{ font-size: 0.85rem; color: var(--muted); margin: 0.15rem 0 0.3rem; }}
  .sec-label {{ font-size: 0.7rem; font-weight: 700; letter-spacing: 0.09em;
    text-transform: uppercase; color: var(--muted); margin: 1.3rem 0 0.45rem;
    display: flex; align-items: center; gap: 0.5rem; }}
  .sec-label .count {{ background: #f0f2f5; color: var(--muted); border-radius: 20px;
    padding: 0.05rem 0.5rem; font-size: 0.65rem; font-weight: 700; }}
  .row {{ display: flex; align-items: center; justify-content: space-between;
    padding: 0.58rem 0.65rem; border-radius: 9px; text-decoration: none;
    color: var(--ink); transition: background 0.12s; }}
  .row:hover {{ background: #f5f7fb; }}
  .row + .row {{ border-top: 1px solid var(--line); }}
  .name {{ font-size: 0.92rem; font-weight: 520; }}
  .when {{ font-size: 0.75rem; color: var(--muted); white-space: nowrap;
    font-variant-numeric: tabular-nums; }}
  .pin .name::before {{ content: "\\2605"; color: var(--star);
    font-size: 0.8rem; margin-right: 0.4rem; }}
  .fresh .when {{ color: #16a34a; font-weight: 600; }}
</style></head>
<body><div class="panel">
  <div class="title">demo-server</div>
  <div class="tagline">{count} modules</div>
  {modules}
</div></body></html>
"""


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


REDIRECT_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Page moved — %%SLUG%%</title>
<meta http-equiv="refresh" content="%%SECONDS%%;url=%%TARGET_ATTR%%">
<style>
  :root { --bg:#f0f2f5; --card:#fff; --fg:#1a1a2e; --muted:#6b7280; --accent:#2563eb; --cat:#1a1a2e; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#16161f; --card:#1f1f2b; --fg:#e8e8ea; --muted:#9ca3af; --accent:#60a5fa; --cat:#e8e8ea; }
  }
  * { box-sizing:border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans TC",sans-serif;
    background:var(--bg); color:var(--fg); padding:1.5rem; }
  .card { background:var(--card); border-radius:16px; box-shadow:0 8px 30px rgba(0,0,0,.12);
    padding:2.6rem 2.2rem; max-width:440px; width:100%; text-align:center; }
  .cat { width:120px; height:120px; color:var(--cat); margin:0 auto .6rem; }
  .cat svg { width:100%; height:100%; display:block; }
  h1 { font-size:1.45rem; margin:.3rem 0 .7rem; }
  .desc { color:var(--muted); font-size:.98rem; margin:0 0 1.3rem; }
  .slug { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; background:rgba(127,127,127,.14);
    padding:.12rem .45rem; border-radius:5px; font-size:.92em; }
  .count { font-size:.95rem; color:var(--muted); margin:1.3rem 0 1.1rem; }
  .count b { color:var(--accent); font-size:1.15rem; }
  .btn { display:inline-block; background:var(--accent); color:#fff; text-decoration:none;
    padding:.65rem 1.6rem; border-radius:9px; font-weight:600; font-size:1rem;
    transition:opacity .15s, transform .15s; }
  .btn:hover { opacity:.9; transform:translateY(-1px); }
  .url { margin-top:1.1rem; font-size:.8rem; }
  .url a { color:var(--muted); word-break:break-all; }
</style>
</head>
<body>
  <div class="card">
    <div class="cat">%%CAT%%</div>
    <h1>This page has moved 🐾</h1>
    <p class="desc">%%DESC%%</p>
    <p><span class="slug">/%%SLUG%%</span> has a new home.</p>
    <p class="count">Redirecting in <b id="n">%%SECONDS%%</b> seconds…</p>
    <a class="btn" href="%%TARGET_ATTR%%">Go now →</a>
    <p class="url"><a href="%%TARGET_ATTR%%">%%TARGET_ATTR%%</a></p>
  </div>
  <script>
    var n = %%SECONDS%%;
    var el = document.getElementById("n");
    var timer = setInterval(function () {
      n -= 1;
      if (n <= 0) { n = 0; clearInterval(timer); }
      if (el) { el.textContent = n; }
    }, 1000);
    setTimeout(function () { window.location.href = %%TARGET_JS%%; }, %%SECONDS%% * 1000);
  </script>
</body>
</html>
"""

ASSETS_DIR = Path(__file__).resolve().parent / "assets"
_redirect_cat_cache: str | None = None


def _redirect_cat_svg() -> str:
    global _redirect_cat_cache
    if _redirect_cat_cache is None:
        try:
            _redirect_cat_cache = (ASSETS_DIR / "redirect-cat.svg").read_text()
        except OSError:
            _redirect_cat_cache = ""
    return _redirect_cat_cache


def _match_redirect(config: dict, module: str) -> dict | None:
    for item in config.get("redirect-modules", []):
        if item.get("slug") == module:
            return item
    return None


def _render_redirect(slug: str, target: str, description: str, seconds: int | str = 5) -> str:
    try:
        seconds = max(0, int(seconds))
    except (TypeError, ValueError):
        seconds = 5
    return (
        REDIRECT_PAGE
        .replace("%%CAT%%", _redirect_cat_svg())
        .replace("%%SECONDS%%", str(seconds))
        .replace("%%SLUG%%", html.escape(slug))
        .replace("%%DESC%%", html.escape(description or ""))
        .replace("%%TARGET_ATTR%%", html.escape(target, quote=True))
        .replace("%%TARGET_JS%%", json.dumps(target))
    )


RECENT_WINDOW = 30 * 86400  # modules updated within 30 days count as "Recent"


def _module_mtime(module_dir: Path) -> float:
    """Update time of a module = mtime of its newest file (recursive).

    Dotfiles (e.g. .DS_Store) are skipped so editor/OS noise doesn't skew the
    time. Falls back to the directory's own mtime if it holds no regular files.
    """
    newest = 0.0
    for f in module_dir.rglob("*"):
        if f.name.startswith(".") or not f.is_file():
            continue
        try:
            mtime = f.stat().st_mtime
        except OSError:
            continue
        if mtime > newest:
            newest = mtime
    if newest == 0.0:
        try:
            newest = module_dir.stat().st_mtime
        except OSError:
            newest = 0.0
    return newest


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
    async def root_auth(request: Request, passcode: str = Form(...)):
        encrypt_file = base / ".encrypt"
        if not encrypt_file.exists():
            return HTMLResponse("Not found", status_code=404)

        client_ip = request.client.host if request.client else "unknown"
        if limiter.is_limited(f"{client_ip}:__root__"):
            return HTMLResponse("Too many attempts. Try again later.", status_code=429)

        stored = encrypt_file.read_text().strip()
        if not verify_passcode(passcode, stored):
            html = PASSCODE_FORM.format(
                module="all", error='<p class="error">Wrong passcode.</p>',
            )
            return HTMLResponse(html, status_code=403)

        response = RedirectResponse("/all/", status_code=303)
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
                html = PASSCODE_FORM.format(module="all", error="")
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

        return WELCOME_PAGE.format(count=len(mtimes), modules=modules_html)

    @app.post("/{module}/__auth__")
    async def auth(module: str, request: Request, passcode: str = Form(...)):
        module_dir = base / module
        encrypt_file = module_dir / ".encrypt"
        if not module_dir.is_dir() or not encrypt_file.exists():
            return HTMLResponse("Not found", status_code=404)

        client_ip = request.client.host if request.client else "unknown"
        if limiter.is_limited(f"{client_ip}:{module}"):
            return HTMLResponse("Too many attempts. Try again later.", status_code=429)

        stored = encrypt_file.read_text().strip()
        if not verify_passcode(passcode, stored):
            html = PASSCODE_FORM.format(
                module=module,
                error='<p class="error">Wrong passcode.</p>',
            )
            return HTMLResponse(html, status_code=403)

        response = RedirectResponse(f"/{module}/", status_code=303)
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
                _render_redirect(
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
                html = PASSCODE_FORM.format(module=module, error="")
                return HTMLResponse(html, status_code=401)

        file_path = (module_dir / path).resolve()
        # Prevent path traversal — append os.sep to avoid prefix collisions
        if not str(file_path).startswith(str(module_dir) + os.sep):
            return HTMLResponse("Forbidden", status_code=403)

        if not file_path.is_file():
            return HTMLResponse("Not found", status_code=404)

        if file_path.suffix == ".md":
            from demo_server.markdown_render import render_md_file
            html_content = render_md_file(file_path)
            return HTMLResponse(html_content)

        return FileResponse(file_path)

    return app
