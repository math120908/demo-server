"""Allowlisted static assets for the Markdown reader UI."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional

STATIC_DIR = Path(__file__).resolve().parent / "static"

# filename -> media type. Nothing outside this mapping is ever served.
ALLOWED = {
    "reader.css": "text/css; charset=utf-8",
    "reader.js": "application/javascript; charset=utf-8",
    "comments.js": "application/javascript; charset=utf-8",
}

_version_cache = None  # type: Optional[str]


def reader_version() -> str:
    """Cache-busting token for asset URLs.

    Assets are served ``immutable`` for a year, so the token must change
    whenever their bytes change. The package version alone is not enough:
    the deploy host is rdev-synced from a local checkout and rarely sees a
    version bump, which would pin every browser to a stale reader forever.
    So the token is a digest of the allowlisted files' contents, computed
    once per process (a restart follows every deploy).
    """
    global _version_cache
    if _version_cache is None:
        digest = hashlib.sha256()
        for name in sorted(ALLOWED):
            path = STATIC_DIR / name
            try:
                digest.update(path.read_bytes())
            except OSError:
                digest.update(name.encode())
        _version_cache = digest.hexdigest()[:12]
    return _version_cache


def asset_path(filename: str) -> Optional[Path]:
    """Resolve an allowlisted asset, or None."""
    if filename not in ALLOWED:
        return None
    path = STATIC_DIR / filename
    return path if path.is_file() else None
