"""Shared pytest fixtures: a temporary DemoDocs-like tree and a TestClient."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from demo_server.server import create_app, hash_passcode

PASSCODE = "s3cret"


@pytest.fixture()
def docs_root(tmp_path):
    """A base dir with one open module and one encrypted module."""
    open_mod = tmp_path / "open-mod"
    (open_mod / "sub").mkdir(parents=True)
    (open_mod / "index.html").write_text("<h1>open index</h1>")
    (open_mod / "notes.md").write_text("# Notes\n\nhello world\n")
    (open_mod / "sub" / "deep.html").write_text("<h1>deep</h1>")

    enc_mod = tmp_path / "enc-mod"
    (enc_mod / "sub").mkdir(parents=True)
    (enc_mod / ".encrypt").write_text(hash_passcode(PASSCODE))
    (enc_mod / "index.html").write_text("<h1>enc index</h1>")
    (enc_mod / "secret.md").write_text("# Secret\n\nclassified\n")
    (enc_mod / "sub" / "deep.html").write_text("<h1>enc deep</h1>")
    return tmp_path


@pytest.fixture()
def client(docs_root):
    return TestClient(create_app(str(docs_root)))
