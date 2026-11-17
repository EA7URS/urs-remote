"""Reservations and reservation quotas (issues #45-64) against the real API.

A member reserves the station in advance (POST /api/v1/reservations), at
least 24 hours ahead, minute-aligned and within the minutes their profile
allows; overlapping windows conflict with 409 and cancellation frees the
slot. A profile without reservation minutes answers canReserve false and
rejects the attempt, and an anonymous client gets 401.

The member client is an explicit requests.Session (bypasses the conftest
cookie shim); the admin work goes through the shimmed module-level API.
"""

import time

import pytest
import requests

from conftest import api_base

MEMBER_ID = "TESTRES1"
MEMBER_TEMP_PASSWORD = "temp-pass-123"
MEMBER_PASSWORD = "member-pass-456"
NOQUOTA_ID = "TESTRES2"
NOQUOTA_TEMP_PASSWORD = "temp-pass-123"
NOQUOTA_PASSWORD = "noquota-pass-789"


def _window():
    """A 30-minute slot 26 hours ahead, minute-aligned and deterministic.

    A fixed offset can collide with leftovers from an interrupted earlier run
    on the same database; the member fixture cancels those first, so the
    window is free when a test starts.
    """
    start = int(time.time()) + 26 * 3600
    start -= start % 60
    return start, start + 1800


def _cancel_confirmed(api, session):
    """Cancel every confirmed reservation of the session's user."""
    r = session.get(f"{api}/reservations", timeout=5)
    r.raise_for_status()
    for rv in r.json()["reservations"]:
        if rv["status"] == "confirmed":
            session.delete(f"{api}/reservations/{rv['id']}", timeout=5)


@pytest.fixture
def member(rest_url, member_session):
    """A member session on a clean slate: no leftover confirmed reservations
    before the test, and none left behind after it, assertion failures
    included (this teardown is what makes the deterministic window safe)."""
    api = api_base(rest_url)
    s = member_session(MEMBER_ID, MEMBER_TEMP_PASSWORD, MEMBER_PASSWORD,
                       maxReservationMinutes=60)
    _cancel_confirmed(api, s)
    yield s
    _cancel_confirmed(api, s)


def test_member_can_reserve_and_cancel(rest_url, member):
    api = api_base(rest_url)
    s = member

    r = s.get(f"{api}/reservations", timeout=5)
    assert r.status_code == 200
    status = r.json()["reservationStatus"]
    assert status["canReserve"] is True
    assert status["maxReservationMinutes"] == 60
    assert status["effectiveReservationMinutes"] > 0
    assert "usage" in r.json()

    start, end = _window()
    r = s.post(f"{api}/reservations", json={"startsAt": start, "endsAt": end}, timeout=5)
    assert r.status_code == 201, r.text
    # Creation returns the id as reservationId; the list pins it as id.
    reservation_id = r.json()["reservationId"]

    r = s.get(f"{api}/reservations", timeout=5)
    assert any(rv["id"] == reservation_id for rv in r.json()["reservations"])

    r = s.delete(f"{api}/reservations/{reservation_id}", timeout=5)
    assert r.status_code == 200, r.text
    r = s.get(f"{api}/reservations", timeout=5)
    mine = [rv for rv in r.json()["reservations"] if rv["id"] == reservation_id]
    # Cancelled reservations stay on the list, marked cancelled.
    assert mine and mine[0]["status"] == "cancelled", r.json()

    # The freed slot can be reserved again; the fixture cancels it afterwards.
    r = s.post(f"{api}/reservations", json={"startsAt": start, "endsAt": end}, timeout=5)
    assert r.status_code == 201, r.text


def test_overlapping_reservation_conflicts(rest_url, member):
    api = api_base(rest_url)
    s = member
    start, end = _window()
    r = s.post(f"{api}/reservations", json={"startsAt": start, "endsAt": end}, timeout=5)
    assert r.status_code == 201, r.text  # the member fixture cleared leftovers

    r = s.post(f"{api}/reservations",
               json={"startsAt": start + 900, "endsAt": end + 900}, timeout=5)
    assert r.status_code == 409, r.text


def test_reservation_beyond_profile_minutes_is_rejected(rest_url, member):
    api = api_base(rest_url)
    s = member
    start, _end = _window()
    r = s.post(f"{api}/reservations",
               json={"startsAt": start, "endsAt": start + 120 * 60}, timeout=5)
    assert r.status_code == 400, r.text


def test_reservation_within_24h_is_rejected(rest_url, member):
    api = api_base(rest_url)
    s = member
    start = int(time.time()) + 3600
    start -= start % 60
    r = s.post(f"{api}/reservations",
               json={"startsAt": start, "endsAt": start + 1800}, timeout=5)
    assert r.status_code == 400, r.text


def test_user_without_minutes_cannot_reserve(rest_url, member_session):
    api = api_base(rest_url)
    s = member_session(NOQUOTA_ID, NOQUOTA_TEMP_PASSWORD, NOQUOTA_PASSWORD,
                       maxReservationMinutes=0)

    r = s.get(f"{api}/reservations", timeout=5)
    assert r.status_code == 200
    assert r.json()["reservationStatus"]["canReserve"] is False

    start, end = _window()
    r = s.post(f"{api}/reservations", json={"startsAt": start, "endsAt": end}, timeout=5)
    assert r.status_code == 400, r.text


def test_anonymous_cannot_read_or_reserve(rest_url):
    api = api_base(rest_url)
    anon = requests.Session()
    assert anon.get(f"{api}/reservations", timeout=5).status_code == 401
    start, end = _window()
    r = anon.post(f"{api}/reservations", json={"startsAt": start, "endsAt": end}, timeout=5)
    assert r.status_code == 401
