"""Role-based access tests for the authenticated web interface.

Covers the three roles the suite must distinguish, against the real login
flow on a test instance with a temporary database (seeded admin EA7URS):

  - anonymous client: every radio and admin endpoint answers 401, and the
    WebSocket control channel (the one that keys PTT) is closed without
    state or command processing;
  - normal (non-admin) user: radio access allowed, admin endpoints denied
    403, including the band-policy write;
  - administrator: admin endpoints allowed.

Anonymous and normal-user clients are explicit ``requests.Session`` objects,
which bypass the conftest cookie shim (that shim only wraps the module-level
``requests.get`` convenience API used by the legacy tests).
"""

import json
import ssl

import pytest
import requests

from conftest import api_base

ADMIN_ID = "EA7URS"
NORMAL_ID = "TESTUSER1"
NORMAL_TEMP_PASSWORD = "temp-pass-123"
NORMAL_PASSWORD = "normal-pass-456"


def test_anonymous_radio_read_is_unauthorized(rest_url):
    r = requests.Session().get(f"{rest_url}/info", timeout=5)
    assert r.status_code == 401


def test_anonymous_radio_write_is_unauthorized(rest_url):
    r = requests.Session().post(f"{rest_url}/frequency",
                                json={"hz": 7074000}, timeout=5)
    assert r.status_code == 401


def test_anonymous_admin_list_is_unauthorized(rest_url):
    r = requests.Session().get(f"{api_base(rest_url)}/admin/users", timeout=5)
    assert r.status_code == 401


def test_anonymous_websocket_gets_no_radio_control(rest_url, wfweb_instance, mock_radio):
    """An unauthenticated WebSocket is closed right after the upgrade.

    The WebSocket is the channel that keys PTT, so it must not process a
    single command without a session: the server logs the rejection and
    closes the socket. The mock radio asserts nothing was keyed.
    """
    websockets = pytest.importorskip("websockets")
    from websockets.sync.client import connect

    _proc, web_port = wfweb_instance
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # No Cookie header: the upgrade succeeds at the TLS/HTTP level, then the
    # server closes the socket because there is no valid wfweb_session.
    ws = connect(f"wss://127.0.0.1:{web_port}", ssl=ctx, open_timeout=10)
    try:
        try:
            ws.send(json.dumps({"cmd": "setPTT", "value": True}))
        except websockets.exceptions.ConnectionClosed:
            pass  # already closed before our command went out: also correct
        with pytest.raises(websockets.exceptions.ConnectionClosed):
            ws.recv(timeout=10)
    finally:
        ws.close()
    assert mock_radio.ptt is False, "an anonymous WebSocket keyed the transmitter"


def test_admin_can_list_users(rest_url):
    # Module-level requests: the shim attaches the admin session cookie.
    r = requests.get(f"{api_base(rest_url)}/admin/users", timeout=5)
    assert r.status_code == 200
    assert any(u["userId"] == ADMIN_ID for u in r.json()["users"])


def test_normal_user_denied_admin_allowed_radio(rest_url, member_session):
    api = api_base(rest_url)
    s = member_session(NORMAL_ID, NORMAL_TEMP_PASSWORD, NORMAL_PASSWORD)

    r = s.get(f"{api}/admin/users", timeout=5)
    assert r.status_code == 403

    r = s.get(f"{rest_url}/info", timeout=5)
    assert r.status_code == 200


def test_normal_user_cannot_set_band_policy(rest_url, member_session):
    """PUT /admin/bands is admin-only: a member gets 403, not a policy change."""
    api = api_base(rest_url)
    s = member_session(NORMAL_ID, NORMAL_TEMP_PASSWORD, NORMAL_PASSWORD)
    r = s.put(f"{api}/admin/bands", json={"allowedBands": [15]}, timeout=5)
    assert r.status_code == 403


def test_wrong_password_is_rejected(rest_url):
    r = requests.Session().post(f"{api_base(rest_url)}/auth/login",
                                json={"userId": ADMIN_ID,
                                      "password": "not-the-password"}, timeout=5)
    assert r.status_code == 401
