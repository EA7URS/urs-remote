"""Shared pytest fixtures for wfweb integration tests.

Provides:
  - mock_radio: async MockIcomRadio server (IC-7610 emulation)
  - wfweb: running wfweb subprocess connected to mock_radio
  - rest_url: base URL for the REST API
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

from mock_radio import MockIcomRadio
from mock_serial_radio import SerialMockRadio

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WFWEB_BIN = PROJECT_ROOT / "wfweb"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_free_port() -> int:
    """Find a free TCP port for the web server."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_rest(url: str, timeout: float = 15.0) -> bool:
    """Poll the REST API until it responds or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                return True
        except requests.ConnectionError:
            pass
        time.sleep(0.3)
    return False


def _wait_for_connected(url: str, timeout: float = 15.0) -> bool:
    """Poll until wfweb reports the rig as connected."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                data = r.json()
                info = data.get("info", data)
                if info.get("connected", False):
                    return True
        except (requests.ConnectionError, requests.JSONDecodeError):
            pass
        time.sleep(0.3)
    return False


def wfweb_output_tail(proc, lines: int = 60) -> str:
    """The last lines wfweb wrote, for a failure message."""
    path = getattr(proc, "output_path", None)
    if not path or not os.path.exists(path):
        return "(no wfweb output file)"
    with open(path, errors="replace") as f:
        return "".join(f.readlines()[-lines:])


def ws_connect(web_port, proc=None, timeout=10.0):
    """A browser-style WebSocket to a test server: WSS on the web port (TLS
    is on by default), plain WS on the next port only where the server runs
    without TLS. An upgrade the server leaves unanswered fails here with the
    server's log tail: it used to fall through to the plain port, whose HTTP
    200 signpost page said nothing about what the WSS path did (macOS CI,
    2026-10-27). Needs the websockets package; skips without it."""
    import ssl
    pytest.importorskip("websockets")
    from websockets.sync.client import connect

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {}
    token = _TEST_SESSIONS.get(web_port)
    if token:
        headers["Cookie"] = f"wfweb_session={token}"
    try:
        return connect(f"wss://127.0.0.1:{web_port}", ssl=ctx, open_timeout=timeout,
                       additional_headers=headers or None)
    except TimeoutError as e:
        tail = wfweb_output_tail(proc) if proc is not None else "(no server handle)"
        pytest.fail(f"WSS upgrade on port {web_port} unanswered for {timeout} s: {e}\n"
                    f"--- wfweb output (tail) ---\n{tail}")
    except (ssl.SSLError, OSError):
        return connect(f"ws://127.0.0.1:{web_port + 1}", open_timeout=timeout,
                       additional_headers=headers or None)


def _dump_and_fail(proc, event_loop, loop_thread, message, url):
    """Kill wfweb, dump its output, stop the event loop, and fail the test."""
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
    print(f"=== wfweb output ({message}) ===", file=sys.stderr)
    print(wfweb_output_tail(proc, 400), file=sys.stderr)
    event_loop.call_soon_threadsafe(event_loop.stop)
    loop_thread.join(timeout=2)
    pytest.fail(f"{message}. URL: {url}")


def _wait_for_cache(status_url: str, timeout: float = 30.0) -> bool:
    """Poll /status until frequency AND mode caches are both populated.

    Mode lands in a later poll cycle than frequency, so waiting only on
    frequency races test_status_has_core_fields.  Timeout is generous
    because slow runners (macOS, Apple Silicon) sometimes take >10 s for
    the first full poll cycle to land.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(status_url, timeout=2)
            if r.status_code == 200:
                data = r.json()
                # frequency/mode are null (not absent) until the first reply
                if ((data.get("frequency") or 0) > 0
                        and isinstance(data.get("mode"), str)
                        and data["mode"]):
                    return True
        except (requests.ConnectionError, requests.JSONDecodeError):
            pass
        time.sleep(0.3)
    return False


# ---------------------------------------------------------------------------
# Mock radio fixture
# ---------------------------------------------------------------------------


_loop_thread = None


def _ensure_loop_thread(event_loop):
    """Run the shared asyncio loop in a daemon thread, started once per session.

    The mock radios need the loop pumped while wfweb handshakes; the thread
    outlives every wfweb instance and is stopped by the event_loop fixture.
    """
    global _loop_thread
    if _loop_thread is None:
        import threading
        started = threading.Event()

        def run_loop():
            asyncio.set_event_loop(event_loop)
            started.set()
            event_loop.run_forever()

        _loop_thread = threading.Thread(target=run_loop, daemon=True)
        _loop_thread.start()
        started.wait()
    return _loop_thread


def _run_on_loop(event_loop, coro):
    """Run a coroutine on the shared loop, whether or not its thread is up yet."""
    if event_loop.is_running():
        return asyncio.run_coroutine_threadsafe(coro, event_loop).result(timeout=10)
    return event_loop.run_until_complete(coro)


@pytest.fixture(scope="session")
def event_loop():
    """Session-scoped event loop for the mock radios."""
    global _loop_thread
    loop = asyncio.new_event_loop()
    yield loop
    if _loop_thread is not None:
        loop.call_soon_threadsafe(loop.stop)
        _loop_thread.join(timeout=2)
        _loop_thread = None
    loop.close()


@pytest.fixture(scope="session")
def mock_radio(event_loop):
    """Start a MockIcomRadio (IC-7610) for the entire test session."""
    server = MockIcomRadio()
    _run_on_loop(event_loop, server.start())
    yield server
    _run_on_loop(event_loop, server.stop())


@pytest.fixture(scope="session")
def mock_radio_7300(event_loop):
    """A second mock answering as an IC-7300 (CI-V 0x94): no command 29, so
    the server addresses the operating VFO through the 25 00 / 26 00 slots."""
    server = MockIcomRadio(radio_addr=0x94)
    _run_on_loop(event_loop, server.start())
    yield server
    _run_on_loop(event_loop, server.stop())



# ---------------------------------------------------------------------------
# Authenticated access to test instances
# ---------------------------------------------------------------------------
# wfweb requires a login for the radio REST API and the WebSocket control
# channel. Every test instance boots with a fresh database seeded with the
# initial admin EA7URS/EA7URS (README), which must replace its password
# before radio access. Tests keep calling plain requests.get(...) etc.; the
# shim below attaches the instance's session cookie to requests aimed at a
# test server, so test bodies stay unchanged and still go through the real
# login flow. No authentication is disabled anywhere.
#
# Scope and isolation of the shim:
# - The cookie is attached ONLY to URLs on host 127.0.0.1/localhost AND a
#   registered test port (web_port or its REST port web_port + 1). Any other
#   host or port goes out untouched; no cookie ever leaves this registry.
# - The registry lives in this pytest process and dies with it; nothing is
#   written outside the per-instance HOME directories (/tmp/wfweb-test*).
# - The shim only wraps the module-level convenience API (requests.get and
#   friends). An explicit requests.Session() does NOT pass through it, which
#   is the sanctioned way to get an anonymous or differently-roled client:
#   see tests/test_auth.py for anonymous (401), normal-user (403 on admin)
#   and admin (allowed) coverage. The legacy tests exercise the admin role,
#   matching their pre-authentication behaviour of full radio access.

_TEST_SESSIONS = {}  # web_port -> wfweb_session token
_TEST_ADMIN_PASSWORD = "wfweb-test-pass"
_requests_shim_installed = False


def _install_requests_shim():
    """Patch requests.api.request once so calls to a test server port carry
    its wfweb_session cookie."""
    global _requests_shim_installed
    if _requests_shim_installed:
        return
    _requests_shim_installed = True
    original = requests.api.request

    def authed_request(method, url, **kwargs):
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            port = parsed.port
        except ValueError:
            host, port = None, None
        if host in ("127.0.0.1", "localhost", "::1") and port is not None:
            for web_port, token in _TEST_SESSIONS.items():
                # REST lives on web_port + 1; both ports share the session.
                if port in (web_port, web_port + 1):
                    headers = dict(kwargs.get("headers") or {})
                    headers.setdefault("Cookie", f"wfweb_session={token}")
                    kwargs["headers"] = headers
                    break
        return original(method, url, **kwargs)

    requests.api.request = authed_request


def _wait_for_listener(url, timeout=15.0):
    """True once the REST listener answers at all (a 401 already means up)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            requests.get(url, timeout=2)
            return True
        except requests.ConnectionError:
            time.sleep(0.3)
    return False


def _login_test_instance(rest_base, web_port):
    """Log the seeded admin in on one test instance and register its session.

    Handles a fresh database (initial password, forced change) and a reused
    one from an earlier run (password already changed).
    """
    s = requests.Session()
    r = s.post(f"{rest_base}/api/v1/auth/login",
               json={"userId": "EA7URS", "password": "EA7URS"}, timeout=5)
    if r.status_code == 401:  # database reused: password already changed
        r = s.post(f"{rest_base}/api/v1/auth/login",
                   json={"userId": "EA7URS", "password": _TEST_ADMIN_PASSWORD}, timeout=5)
    r.raise_for_status()
    if r.json().get("mustChangePassword"):
        r = s.post(f"{rest_base}/api/v1/auth/password",
                   json={"currentPassword": "EA7URS",
                         "newPassword": _TEST_ADMIN_PASSWORD}, timeout=5)
        r.raise_for_status()
    token = s.cookies.get("wfweb_session")
    if not token:
        pytest.fail(f"login on {rest_base} returned no wfweb_session cookie")
    _TEST_SESSIONS[web_port] = token
    _install_requests_shim()


def _unregister_test_session(web_port):
    """Drop the session registered for a stopped instance's web_port.

    Without this the registry grows with every extra instance a test launches
    and a recycled port could inherit a stale cookie."""
    _TEST_SESSIONS.pop(web_port, None)


# ---------------------------------------------------------------------------
# Shared member-user helpers
# ---------------------------------------------------------------------------

def api_base(rest_url):
    """http://127.0.0.1:<rest>/api/v1 base, derived from the radio base URL."""
    return rest_url.rsplit("/radio", 1)[0]


def explicit_login(api, user_id, password):
    """Log in with an explicit requests.Session (bypasses the cookie shim)."""
    s = requests.Session()
    r = s.post(f"{api}/auth/login",
               json={"userId": user_id, "password": password}, timeout=5)
    r.raise_for_status()
    return s, r.json()


@pytest.fixture
def member_session(rest_url):
    """Factory for logged-in explicit sessions of non-admin member users.

    Creates the user through the admin (shimmed) API when needed — the server
    answers 200 on creation and 409 when the database is reused from an
    earlier run — and performs the forced initial-password change, so the
    returned session has full member access. The session bypasses the
    admin-cookie shim.
    """
    def _make(user_id, temp_password, password, **user_fields):
        api = api_base(rest_url)
        payload = {
            "userId": user_id, "password": temp_password,
            "firstName": "Test", "lastName": "User",
            "email": f"{user_id.lower()}@example.invalid",
            "street": "Calle Falsa 1", "city": "Bari",
            "postalCode": "70100", "province": "BA",
        }
        payload.update(user_fields)
        r = requests.post(f"{api}/admin/users", json=payload, timeout=5)
        assert r.status_code in (200, 409), r.text
        try:
            # Fresh user, or a reused user whose previous run crashed before
            # the forced change: the temporary password still applies.
            s, me = explicit_login(api, user_id, temp_password)
        except requests.HTTPError:
            # Reused database: the password was already changed.
            s, _me = explicit_login(api, user_id, password)
            return s
        if me.get("mustChangePassword"):
            r = s.post(f"{api}/auth/password",
                       json={"currentPassword": temp_password,
                             "newPassword": password}, timeout=5)
            r.raise_for_status()
        return s
    return _make

# ---------------------------------------------------------------------------
# wfweb subprocess fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def rigctld_port():
    """Port requested via --rigctld-port for wfweb_instance. With the
    authenticated web interface wfweb refuses to open it (#3); the rigctld
    tests assert that nothing ever listens here."""
    return _find_free_port()


@pytest.fixture(scope="session")
def rigctld_7300_port():
    """Port requested via --rigctld-port for wfweb_7300_instance; expected
    to stay closed while auth is enabled (see rigctld_port)."""
    return _find_free_port()


def _launch_wfweb(mock, event_loop, rigctld_port, civ, home):
    """Start wfweb LAN-connected to mock; return (process, web_port) once the
    rig is connected and its frequency / mode caches are live."""
    if not WFWEB_BIN.exists():
        pytest.skip(f"wfweb binary not found at {WFWEB_BIN} — run 'qmake wfweb.pro && make' first")

    web_port = _find_free_port()
    rest_port = web_port + 1

    cmd = [
        str(WFWEB_BIN),
        "-p", str(web_port),
        "--lan", "127.0.0.1",
        "--lan-control", str(mock.control_port),
        "--lan-user", "testuser",
        "--lan-pass", "testpass",
        "--civ", civ,
        # Deliberately requested even though auth disables rigctld: the
        # regression tests prove the port stays closed in this configuration.
        "--rigctld-port", str(rigctld_port),
    ]

    env = os.environ.copy()
    # Avoid wfweb loading the user's real settings
    env["HOME"] = home
    os.makedirs(home, exist_ok=True)

    # wfweb also logs every line to stdout when it is not on a terminal. A pipe
    # nobody reads fills up (16 KB on macOS) and then blocks every thread that
    # logs, so stdout is dropped; the -l log file, flushed per line, is what
    # failures quote.
    output_path = os.path.join(home, "wfweb.log")
    cmd += ["-l", output_path]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        env=env,
    )
    proc.output_path = output_path

    # The mock's event loop must run in the background to handle the handshake
    loop_thread = _ensure_loop_thread(event_loop)

    rest_base = f"http://127.0.0.1:{rest_port}"
    info_url = f"{rest_base}/api/v1/radio/info"

    if not _wait_for_listener(info_url):
        _dump_and_fail(proc, event_loop, loop_thread,
                       "wfweb REST listener did not come up", info_url)
    _login_test_instance(rest_base, web_port)

    if not _wait_for_connected(info_url, timeout=15.0):
        _dump_and_fail(proc, event_loop, loop_thread,
                       "wfweb did not connect within timeout", info_url)

    # Wait for the first poll cycle to populate frequency AND mode caches
    status_url = f"{rest_base}/api/v1/radio/status"
    if not _wait_for_cache(status_url):
        _dump_and_fail(proc, event_loop, loop_thread,
                       "wfweb cache not populated within timeout", status_url)

    return proc, web_port


def _stop_wfweb(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


@pytest.fixture(scope="session")
def wfweb_instance(mock_radio, event_loop, rigctld_port):
    """Start wfweb connected to mock_radio, yield (process, web_port), stop on teardown."""
    proc, web_port = _launch_wfweb(mock_radio, event_loop, rigctld_port, "0x98", "/tmp/wfweb-test")
    yield proc, web_port
    _stop_wfweb(proc)
    _unregister_test_session(web_port)


@pytest.fixture(scope="session")
def wfweb_7300_instance(mock_radio_7300, event_loop, rigctld_7300_port):
    """wfweb connected to the IC-7300 mock: for the rigctld tests that need the
    Selected / Unselected VFO slots and a mode set that carries the data byte."""
    proc, web_port = _launch_wfweb(mock_radio_7300, event_loop, rigctld_7300_port, "0x94", "/tmp/wfweb-test-7300")
    yield proc, web_port
    _stop_wfweb(proc)
    _unregister_test_session(web_port)


@pytest.fixture(scope="session")
def rest_url(wfweb_instance):
    """Base REST API URL: http://127.0.0.1:<port>/api/v1/radio"""
    _, web_port = wfweb_instance
    return f"http://127.0.0.1:{web_port + 1}/api/v1/radio"


@pytest.fixture(scope="session")
def poll(rest_url):
    """Return a function that polls a REST endpoint until a condition is met.

    Usage::
        data = poll("frequency", lambda d: d.get("hz") == 7074000)
    """
    def _poll(endpoint, predicate, timeout=5.0):
        url = f"{rest_url}/{endpoint}"
        deadline = time.monotonic() + timeout
        last_data = None
        while time.monotonic() < deadline:
            try:
                r = requests.get(url, timeout=2)
                if r.status_code == 200:
                    last_data = r.json() if r.text else {}
                    if predicate(last_data):
                        return last_data
            except (requests.ConnectionError, requests.JSONDecodeError):
                pass
            time.sleep(0.2)
        pytest.fail(f"poll({endpoint}) timed out. Last: {last_data}")
    return _poll


# ---------------------------------------------------------------------------
# USB/serial mock fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def serial_mock():
    """Start a SerialMockRadio (PTY-based) for the entire test session."""
    server = SerialMockRadio()
    server.start()
    yield server
    server.stop()


@pytest.fixture(scope="session")
def usb_wfweb_instance(serial_mock):
    """Start wfweb connected to serial_mock via PTY, yield (process, web_port)."""
    if not WFWEB_BIN.exists():
        pytest.skip(f"wfweb binary not found at {WFWEB_BIN}")

    web_port = _find_free_port()
    rest_port = web_port + 1

    cmd = [
        str(WFWEB_BIN),
        "-p", str(web_port),
        "--serial-port", serial_mock.port_path,
        "--civ", "0x98",
    ]

    env = os.environ.copy()
    env["HOME"] = "/tmp/wfweb-test-usb"
    os.makedirs("/tmp/wfweb-test-usb", exist_ok=True)

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )

    rest_base = f"http://127.0.0.1:{rest_port}"
    info_url = f"{rest_base}/api/v1/radio/info"

    if not _wait_for_listener(info_url):
        proc.terminate()
        proc.kill()
        pytest.fail(f"wfweb (USB) REST listener did not come up. PTY: {serial_mock.port_path}")
    _login_test_instance(rest_base, web_port)

    if not _wait_for_connected(info_url, timeout=15.0):
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=3)
            print(f"=== wfweb USB output ===", file=sys.stderr)
            print(out.decode(errors="replace"), file=sys.stderr)
        except subprocess.TimeoutExpired:
            proc.kill()
        pytest.fail(f"wfweb (USB) did not connect. PTY: {serial_mock.port_path}")

    status_url = f"{rest_base}/api/v1/radio/status"
    if not _wait_for_cache(status_url):
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=3)
            print(f"=== wfweb USB output (cache) ===", file=sys.stderr)
            print(out.decode(errors="replace"), file=sys.stderr)
        except subprocess.TimeoutExpired:
            proc.kill()
        pytest.fail("wfweb (USB) cache not populated")

    yield proc, web_port

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)
    _unregister_test_session(web_port)


@pytest.fixture(scope="session")
def usb_rest_url(usb_wfweb_instance):
    """Base REST API URL for the USB-connected wfweb instance."""
    _, web_port = usb_wfweb_instance
    return f"http://127.0.0.1:{web_port + 1}/api/v1/radio"


@pytest.fixture(scope="session")
def usb_poll(usb_rest_url):
    """Poll fixture for the USB-connected wfweb instance."""
    def _poll(endpoint, predicate, timeout=5.0):
        url = f"{usb_rest_url}/{endpoint}"
        deadline = time.monotonic() + timeout
        last_data = None
        while time.monotonic() < deadline:
            try:
                r = requests.get(url, timeout=2)
                if r.status_code == 200:
                    last_data = r.json() if r.text else {}
                    if predicate(last_data):
                        return last_data
            except (requests.ConnectionError, requests.JSONDecodeError):
                pass
            time.sleep(0.2)
        pytest.fail(f"usb_poll({endpoint}) timed out. Last: {last_data}")
    return _poll


def pytest_configure(config):
    """Registered markers: slow = long real-time waits (quota exhaustion,
    ~70 s). Deselect with -m "not slow"."""
    config.addinivalue_line(
        "markers", "slow: long real-time waits (e.g. quota exhaustion)")
