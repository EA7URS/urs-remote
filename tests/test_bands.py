"""Band policy enforcement (issues #65-68) against the mock radio.

An admin pins the bands the club station may use (PUT /api/v1/admin/bands).
With a policy in place every tuning path must refuse frequencies outside it
without the radio ever receiving the forbidden command, and the station must
recover by returning to 14.100 MHz, the one frequency that is always
allowed. Without a policy everything is allowed, and a saved policy must
survive a process restart.
"""

import json
import shutil
import time

import pytest
import requests

from conftest import (MockIcomRadio, _find_free_port, _launch_wfweb,
                      _run_on_loop, _stop_wfweb, ws_connect)
from mock_civ import bcd_decode_freq

BAND_20M = 15  # availableBands enum (rigidentities.h)
FORBIDDEN_HZ = 14_200_000  # inside 20m
FALLBACK_HZ = 14_100_000   # always allowed, even with 20m forbidden
ALLOWED_HZ = 7_100_000     # 40m


def _bands(rest_base):
    r = requests.get(f"{rest_base}/admin/bands", timeout=5)
    assert r.status_code == 200
    return r.json()


def _set_policy(rest_base, nums):
    r = requests.put(f"{rest_base}/admin/bands",
                     json={"allowedBands": nums}, timeout=5)
    assert r.status_code == 200
    return r.json()


def _rest_base(web_port):
    return f"http://127.0.0.1:{web_port + 1}/api/v1"


@pytest.fixture(scope="module")
def policy(rest_url):
    """A policy that forbids 20m on the shared instance, undone on teardown.

    The policy lives in the instance database, which other test files share,
    so leaving a restrictive set behind would break them.
    """
    rest_base = rest_url.rsplit("/radio", 1)[0]
    all_bands = [b["num"] for b in _bands(rest_base)["bands"]]
    assert BAND_20M in all_bands, "the IC-7610 should advertise 20m"
    _set_policy(rest_base, [b for b in all_bands if b != BAND_20M])
    yield
    _set_policy(rest_base, all_bands)
    # The recoveries in this module park the dial on 14.100 MHz; put it back
    # where the other test files expect it (the mock's 14.074 MHz default).
    requests.put(f"{rest_base}/radio/frequency", json={"hz": 14_074_000}, timeout=5)


def test_policy_roundtrip(rest_url, policy):
    """GET reflects the saved policy, marked as configured."""
    data = _bands(rest_url.rsplit("/radio", 1)[0])
    assert data["configured"] is True
    assert BAND_20M not in data["allowedBands"]
    assert data["allowedBands"] == sorted(data["allowedBands"])


def test_rest_rejects_forbidden_frequency(rest_url, poll, policy):
    """PUT /frequency inside a forbidden band answers 409 band_restricted.

    The policy fixture itself forbids the band the radio starts in, so the
    automatic recovery has already steered it to 14.100 MHz here; polling
    confirms that fallback.
    """
    r = requests.put(f"{rest_url}/frequency", json={"hz": FORBIDDEN_HZ}, timeout=5)
    assert r.status_code == 409
    body = r.json()
    assert body["code"] == "band_restricted"
    assert body["fallbackHz"] == FALLBACK_HZ
    poll("frequency", lambda d: d.get("hz") == FALLBACK_HZ, timeout=10)


def _frequency_writes(frames, hz):
    """CI-V frames in the log that tune the rig to hz: a plain set-frequency
    (cmd 05) or a selected-VFO write (cmd 25, sub 00)."""
    out = []
    for f in frames:
        if len(f) < 11 or f[0] != 0xFE or f[1] != 0xFE:
            continue
        if f[4] == 0x05 and bcd_decode_freq(bytes(f[5:10])) == hz:
            out.append(bytes(f))
        elif f[4] == 0x25 and f[5] == 0x00 and bcd_decode_freq(bytes(f[6:11])) == hz:
            out.append(bytes(f))
    return out


def test_rig_never_receives_the_forbidden_command(rest_url, poll, mock_radio, policy):
    """No CI-V frequency write to the forbidden frequency reaches the radio.

    The mock's civ_log records every frame the server sends, so unlike
    sampling the dial this cannot miss a transient forbidden write.
    Recovery re-tunes at most once per 10s window (anti-flap), so this test
    does not assert where the rig lands, only that it never goes forbidden.
    """
    requests.put(f"{rest_url}/frequency", json={"hz": ALLOWED_HZ}, timeout=5)
    poll("frequency", lambda d: d.get("hz") == ALLOWED_HZ)

    mark = len(mock_radio.civ_log)
    requests.put(f"{rest_url}/frequency", json={"hz": FORBIDDEN_HZ}, timeout=5)
    time.sleep(2)  # let the server settle; a leaked write would land within this
    data = requests.get(f"{rest_url}/frequency", timeout=5).json()
    assert data["hz"] in (ALLOWED_HZ, FALLBACK_HZ)
    leaked = _frequency_writes(mock_radio.civ_log[mark:], FORBIDDEN_HZ)
    assert not leaked, f"a set-frequency command for {FORBIDDEN_HZ} Hz reached the radio: {leaked!r}"


def test_fallback_frequency_is_always_allowed(rest_url, policy):
    """14.100 MHz is accepted even though its band is not in the policy."""
    r = requests.put(f"{rest_url}/frequency", json={"hz": FALLBACK_HZ}, timeout=5)
    assert r.status_code == 202


def test_websocket_rejection_notifies_the_client(rest_url, wfweb_instance, poll, policy):
    """setFrequency over WS is refused with a bandRestricted notice + recovery."""
    proc, web_port = wfweb_instance
    requests.put(f"{rest_url}/frequency", json={"hz": ALLOWED_HZ}, timeout=5)
    poll("frequency", lambda d: d.get("hz") == ALLOWED_HZ)

    ws = ws_connect(web_port, proc)
    try:
        ws.send(json.dumps({"cmd": "setFrequency", "value": FORBIDDEN_HZ}))
        deadline = time.monotonic() + 5
        notice = None
        while time.monotonic() < deadline and notice is None:
            msg = json.loads(ws.recv(timeout=5))
            if msg.get("type") == "bandRestricted":
                notice = msg
        assert notice is not None, "no bandRestricted notice within 5s"
        assert notice["requestedHz"] == FORBIDDEN_HZ
        assert notice["fallbackHz"] == FALLBACK_HZ
    finally:
        ws.close()
    data = requests.get(f"{rest_url}/frequency", timeout=5).json()
    assert data["hz"] in (ALLOWED_HZ, FALLBACK_HZ)


@pytest.fixture(scope="module")
def fresh_pair(event_loop):
    """A wfweb with its own mock and HOME, for the no-policy and restart cases."""
    home = "/tmp/wfweb-test-bands"
    shutil.rmtree(home, ignore_errors=True)
    radio = MockIcomRadio()
    _run_on_loop(event_loop, radio.start())
    proc, web_port = _launch_wfweb(radio, event_loop, _find_free_port(), "0x98", home)
    yield radio, proc, web_port, home
    _stop_wfweb(proc)
    _run_on_loop(event_loop, radio.stop())


def test_without_policy_everything_is_allowed(fresh_pair):
    """A fresh database has no policy: any frequency is accepted."""
    _radio, _proc, web_port, _home = fresh_pair
    rest_base = _rest_base(web_port)
    assert _bands(rest_base)["configured"] is False
    r = requests.put(f"{rest_base}/radio/frequency", json={"hz": FORBIDDEN_HZ}, timeout=5)
    assert r.status_code == 202


def test_policy_survives_a_restart(fresh_pair, event_loop):
    """Same HOME, new process: the saved policy is still enforced."""
    radio, proc, web_port, home = fresh_pair
    rest_base = _rest_base(web_port)
    all_bands = [b["num"] for b in _bands(rest_base)["bands"]]
    _set_policy(rest_base, [b for b in all_bands if b != BAND_20M])

    _stop_wfweb(proc)
    proc2, web_port2 = _launch_wfweb(radio, event_loop, _find_free_port(), "0x98", home)
    try:
        rest_base2 = _rest_base(web_port2)
        data = _bands(rest_base2)
        assert data["configured"] is True
        assert BAND_20M not in data["allowedBands"]
        r = requests.put(f"{rest_base2}/radio/frequency", json={"hz": FORBIDDEN_HZ}, timeout=5)
        assert r.status_code == 409
    finally:
        _stop_wfweb(proc2)
