"""Unit tests for post-login redirect target validation."""

from __future__ import annotations

import pytest

from demo_server.server import safe_next


@pytest.mark.parametrize(
    "candidate",
    [
        "/enc-mod/",
        "/enc-mod/sub/deep.html",
        "/enc-mod/notes.md?raw=1",
        "/enc-mod",
    ],
)
def test_safe_next_accepts_in_module_paths(candidate):
    assert safe_next(candidate, "enc-mod") == candidate


@pytest.mark.parametrize(
    "candidate",
    [
        "",
        None,
        "https://evil.com/",
        "//evil.com/",
        "/\\evil.com",
        "\\\\evil.com",
        "/other-mod/index.html",
        "/enc-mod/../other-mod/index.html",
        "/enc-mod-evil/index.html",
        "enc-mod/index.html",
        "/enc-mod/\nSet-Cookie: x=1",
    ],
)
def test_safe_next_rejects_hostile_targets(candidate):
    assert safe_next(candidate, "enc-mod") == "/enc-mod/"


def test_safe_next_root_scope():
    assert safe_next("/all/", "__root__") == "/all/"
    assert safe_next("/enc-mod/", "__root__") == "/all/"


from tests.conftest import PASSCODE  # noqa: E402


def test_deep_path_401_carries_next(client):
    r = client.get("/enc-mod/sub/deep.html")
    assert r.status_code == 401
    assert 'name="next" value="/enc-mod/sub/deep.html"' in r.text


def test_login_redirects_to_next(client):
    r = client.post(
        "/enc-mod/__auth__",
        data={"passcode": PASSCODE, "next": "/enc-mod/sub/deep.html"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/enc-mod/sub/deep.html"


def test_login_rejects_offsite_next(client):
    r = client.post(
        "/enc-mod/__auth__",
        data={"passcode": PASSCODE, "next": "https://evil.com/"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/enc-mod/"


def test_login_without_next_uses_module_root(client):
    r = client.post(
        "/enc-mod/__auth__", data={"passcode": PASSCODE}, follow_redirects=False
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/enc-mod/"


def test_wrong_passcode_preserves_next(client):
    r = client.post(
        "/enc-mod/__auth__",
        data={"passcode": "nope", "next": "/enc-mod/sub/deep.html"},
    )
    assert r.status_code == 403
    assert 'name="next" value="/enc-mod/sub/deep.html"' in r.text
    assert "Wrong passcode" in r.text


def test_query_string_preserved_in_next(client):
    r = client.get("/enc-mod/secret.md?raw=1")
    assert r.status_code == 401
    assert 'value="/enc-mod/secret.md?raw=1"' in r.text
