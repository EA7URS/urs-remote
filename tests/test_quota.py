"""Usage quota enforcement (issues #45-64): PTT release at the daily limit.

A member's connected time counts against the usage profile an admin assigns
them. When the daily allowance runs out mid-transmission the server must
release the PTT, notify the client with usageLimitDenied, close the socket
and refuse the next connection; the quota then shows as exhausted over REST.

The member's WebSocket and REST calls use an explicit session, bypassing the
conftest admin-cookie shim; the admin work (profile, user, usage reset) goes
through the shimmed module-level API.

Both tests are marked slow: exhausting a one-minute allowance takes real
time (the server checks usage once per second, so the wait is ~60-70 s).
"""

import json
import ssl
import time

import pytest
import requests

from conftest import api_base

websockets = pytest.importorskip("websockets")
from websockets.sync.client import connect

QUOTA_ID = "TESTQUOTA"
QUOTA_TEMP_PASSWORD = "temp-pass-123"
QUOTA_PASSWORD = "quota-pass-456"
PROFILE_NAME = "Cuota de prueba 1 min"


def _profile_id(api):
    r = requests.get(f"{api}/admin/usage-profiles", timeout=5)
    r.raise_for_status()
    for p in r.json()["profiles"]:
        if p.get("name") == PROFILE_NAME:
            return p["profileId"]
    r = requests.post(f"{api}/admin/usage-profiles",
                      json={"name": PROFILE_NAME, "dailyLimitMinutes": 1}, timeout=5)
    assert r.status_code == 201, r.text
    return r.json()["profileId"]


@pytest.fixture
def quota_user(rest_url, member_session):
    """Quota member with a 1-minute daily profile and the day reset."""
    api = api_base(rest_url)
    profile_id = _profile_id(api)
    s = member_session(QUOTA_ID, QUOTA_TEMP_PASSWORD, QUOTA_PASSWORD,
                       maxReservationMinutes=0, usageProfileId=profile_id)
    # Reused databases carry spent allowance from earlier runs: reset the day.
    requests.post(f"{api}/admin/users/{QUOTA_ID}/usage-reset",
                  json={"period": "daily"}, timeout=5).raise_for_status()
    return s


def _ws_as(session, web_port):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    token = session.cookies.get("wfweb_session")
    return connect(f"wss://127.0.0.1:{web_port}", ssl=ctx, open_timeout=10,
                   additional_headers={"Cookie": f"wfweb_session={token}"})


def _wait_mock_ptt(mock_radio, state, timeout=10.0):
    """The server cache answers before the CI-V write reaches the radio, so
    the mock state needs its own poll, like the REST one."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if mock_radio.ptt is state:
            return
        time.sleep(0.1)
    pytest.fail(f"mock radio PTT did not reach {state} within {timeout} s")


def _spend_daily_quota(session, web_port, mock_radio, poll):
    """Transmit until the server cuts the PTT at the daily limit.

    Asserts the full denial path: usageLimitDenied notice, socket closed by
    the server, REST cache back to receive and the PTT-off CI-V command
    (1C 00 00) on the wire, not just the server's word.
    """
    mark = len(mock_radio.civ_log)
    ws = _ws_as(session, web_port)
    try:
        ws.send(json.dumps({"cmd": "setPTT", "value": True}))
        poll("ptt", lambda d: d.get("transmitting") is True, timeout=5.0)
        _wait_mock_ptt(mock_radio, True)

        # One minute of allowance: the server checks every second, so the
        # denial must land well inside 90 s.
        notice = None
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline and notice is None:
            try:
                msg = json.loads(ws.recv(timeout=90))
            except Exception:
                break  # closed by the server after the denial
            if msg.get("type") == "usageLimitDenied":
                notice = msg
        assert notice is not None, "no usageLimitDenied within 90 s of PTT"
    finally:
        try:
            ws.close()
        except Exception:
            pass

    poll("ptt", lambda d: d.get("transmitting") is False, timeout=5.0)
    _wait_mock_ptt(mock_radio, False)
    ptt_off_frames = [f for f in mock_radio.civ_log[mark:]
                      if bytes(f[4:7]) == b"\x1c\x00\x00"]
    assert ptt_off_frames, "no PTT-off command (1C 00 00) reached the radio"


@pytest.mark.slow
def test_ptt_is_released_when_the_daily_quota_runs_out(rest_url, wfweb_instance, mock_radio, poll, quota_user):
    api = api_base(rest_url)
    _proc, web_port = wfweb_instance

    r = quota_user.get(f"{api}/reservations", timeout=5)
    usage = r.json()["usage"]
    assert usage["allowed"] is True
    assert usage["profileName"] == PROFILE_NAME

    _spend_daily_quota(quota_user, web_port, mock_radio, poll)

    r = quota_user.get(f"{api}/reservations", timeout=5)
    assert r.json()["usage"]["allowed"] is False


@pytest.mark.slow
def test_exhausted_user_cannot_reconnect(rest_url, wfweb_instance, mock_radio, poll, quota_user):
    """A new socket with the quota spent gets an immediate usageLimitDenied.

    Standalone: the quota_user fixture resets the day and this test spends
    the allowance itself, so it does not rely on running after the previous
    test.
    """
    api = api_base(rest_url)
    _proc, web_port = wfweb_instance

    _spend_daily_quota(quota_user, web_port, mock_radio, poll)

    ws = _ws_as(quota_user, web_port)
    try:
        msg = json.loads(ws.recv(timeout=10))
        assert msg.get("type") == "usageLimitDenied", msg
    finally:
        try:
            ws.close()
        except Exception:
            pass
