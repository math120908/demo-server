"""Tests for the /__reader__/ asset route and the ?raw=1 source view."""

from __future__ import annotations

from tests.conftest import PASSCODE


def test_reader_asset_served(client):
    r = client.get("/__reader__/reader.css")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/css")
    assert "immutable" in r.headers.get("cache-control", "")


def test_reader_asset_js_served(client):
    for name in ("reader.js", "comments.js"):
        r = client.get("/__reader__/" + name)
        assert r.status_code == 200
        assert "javascript" in r.headers["content-type"]


def test_reader_asset_rejects_unknown_file(client):
    assert client.get("/__reader__/secrets.txt").status_code == 404


def test_reader_asset_rejects_traversal(client):
    for path in ("/__reader__/../server.py", "/__reader__/%2e%2e/server.py"):
        assert client.get(path).status_code in (403, 404)


def test_raw_returns_plain_markdown(client):
    r = client.get("/open-mod/notes.md?raw=1")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert r.text == "# Notes\n\nhello world\n"


def test_without_raw_returns_rendered_html(client):
    r = client.get("/open-mod/notes.md")
    assert r.status_code == 200
    assert "<h1" in r.text


def test_raw_ignored_for_non_markdown(client):
    r = client.get("/open-mod/index.html?raw=1")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")


def test_raw_still_requires_passcode(client):
    r = client.get("/enc-mod/secret.md?raw=1")
    assert r.status_code == 401
    assert "classified" not in r.text


def test_raw_works_after_login(client):
    client.post(
        "/enc-mod/__auth__", data={"passcode": PASSCODE, "next": "/enc-mod/"}
    )
    r = client.get("/enc-mod/secret.md?raw=1")
    assert r.status_code == 200
    assert "classified" in r.text


def test_rendered_page_links_reader_assets(client):
    r = client.get("/open-mod/notes.md")
    assert "/__reader__/reader.css?v=" in r.text
    assert "/__reader__/reader.js?v=" in r.text
    assert "/__reader__/comments.js?v=" in r.text
    assert 'id="mdr-rail"' in r.text
