import os
import secrets
from pathlib import Path

from fastapi import FastAPI, Request, Form
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from itsdangerous import URLSafeSerializer

BASE_DIR = Path.home() / ".demo-server"
SECRET_FILE = BASE_DIR / ".secret"


def _get_secret() -> str:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text().strip()
    secret = secrets.token_hex(32)
    SECRET_FILE.write_text(secret)
    return secret


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
<html><head><title>demo-server</title>
<style>
  body {{ font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }}
  .box {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,.1); text-align: center; }}
  ul {{ text-align: left; }}
</style></head>
<body><div class="box">
  <h1>demo-server</h1>
  <p>Available modules:</p>
  <ul>{modules}</ul>
</div></body></html>
"""


def create_app(base_path: str) -> FastAPI:
    base = Path(base_path).resolve()
    secret = _get_secret()
    serializer = URLSafeSerializer(secret)
    app = FastAPI()

    @app.get("/", response_class=HTMLResponse)
    async def home():
        return ""

    @app.get("/all/", response_class=HTMLResponse)
    async def listing():
        modules = ""
        for entry in sorted(base.iterdir()):
            if entry.is_dir() and not entry.name.startswith("."):
                modules += f'<li><a href="/{entry.name}/">{entry.name}</a></li>'
        return WELCOME_PAGE.format(modules=modules)

    @app.post("/{module}/__auth__")
    async def auth(module: str, passcode: str = Form(...)):
        module_dir = base / module
        encrypt_file = module_dir / ".encrypt"
        if not module_dir.is_dir() or not encrypt_file.exists():
            return HTMLResponse("Not found", status_code=404)

        expected = encrypt_file.read_text().strip()
        if passcode != expected:
            html = PASSCODE_FORM.format(
                module=module,
                error='<p class="error">Wrong passcode.</p>',
            )
            return HTMLResponse(html, status_code=403)

        response = RedirectResponse(f"/{module}/", status_code=303)
        token = serializer.dumps(module)
        response.set_cookie(f"auth_{module}", token, httponly=True)
        return response

    @app.get("/{module}/{path:path}")
    async def serve(module: str, request: Request, path: str = ""):
        module_dir = base / module
        if not module_dir.is_dir():
            return HTMLResponse("Not found", status_code=404)

        if not path or path.endswith("/"):
            path = path + "index.html"

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
                value = serializer.loads(cookie) if cookie else None
            except Exception:
                value = None
            if value != module:
                html = PASSCODE_FORM.format(module=module, error="")
                return HTMLResponse(html, status_code=401)

        file_path = (module_dir / path).resolve()
        # Prevent path traversal
        if not str(file_path).startswith(str(module_dir)):
            return HTMLResponse("Forbidden", status_code=403)

        if not file_path.is_file():
            return HTMLResponse("Not found", status_code=404)

        return FileResponse(file_path)

    return app
