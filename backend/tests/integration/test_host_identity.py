"""
Host identity (ADR-125).

The dashboard's host card had to leave hostname, address and uptime
blank because nothing reported them — and the one number it could show,
`uptime_seconds`, was the **API process's**, not the machine's. Putting
that under a "Uptime" label beside hostname and IP would have read as
the host's uptime, which is a different quantity entirely.

These tests pin that the two uptimes stay distinguishable, that an
unreadable field comes back null with a reason rather than as zero, and
that identifying the host sends nothing.
"""

from __future__ import annotations

import builtins

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def get_host(client) -> dict:
    response = client.get("/api/v1/system/host")
    assert response.status_code == 200
    return response.json()


def test_host_uptime_is_not_the_process_uptime(client):
    """
    The regression this endpoint exists to prevent.

    A process that started seconds ago on a machine up for hours must
    not report the machine as seconds old.
    """
    body = get_host(client)

    assert "process_uptime_seconds" in body
    assert body["process_uptime_seconds"] >= 0

    if body["host_uptime_seconds"] is not None:
        # The process cannot predate the machine it runs on.
        assert body["host_uptime_seconds"] >= body["process_uptime_seconds"]


def test_the_machine_is_identified(client):
    body = get_host(client)
    assert body["hostname"], "the host reports a name; it should be carried"
    assert body["operating_system"]


def test_an_unreadable_uptime_is_null_with_a_reason_never_zero(monkeypatch):
    """
    `psutil` is not a declared dependency and `/proc/uptime` does not
    exist everywhere. Where neither is available the figure is absent —
    and absent is null, because 0 would claim the machine just booted.
    """
    real_import = builtins.__import__

    def no_psutil(name, *args, **kwargs):
        if name == "psutil":
            raise ImportError("psutil is not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_psutil)

    def no_proc(*args, **kwargs):
        raise OSError("no /proc on this platform")

    monkeypatch.setattr(builtins, "open", no_proc)

    from app.api.v1.system_health import _read_host_uptime

    value, reason, source = _read_host_uptime()

    assert value is None, "an unreadable uptime must be null, never 0"
    assert reason and "psutil" in reason
    assert source is None


def test_identifying_the_host_opens_no_connection(monkeypatch):
    """
    Reading the local address must not contact anything.

    A UDP `connect` only fixes the route and sends no packet. If this
    ever became a real connection, PraHari would be reaching out to a
    third party just to render a card.
    """
    import socket as socket_module

    sent: list = []
    real_socket = socket_module.socket

    class WatchedSocket(real_socket):  # type: ignore[misc, valid-type]
        def send(self, *args, **kwargs):  # noqa: D102
            sent.append(args)
            return super().send(*args, **kwargs)

        def sendall(self, *args, **kwargs):  # noqa: D102
            sent.append(args)
            return super().sendall(*args, **kwargs)

        def sendto(self, *args, **kwargs):  # noqa: D102
            sent.append(args)
            return super().sendto(*args, **kwargs)

    monkeypatch.setattr(socket_module, "socket", WatchedSocket)

    from app.api.v1.system_health import _read_local_ip

    _read_local_ip()

    assert sent == [], "identifying the host must not transmit anything"


def test_the_address_is_labelled_as_a_route_choice_not_a_capability(client):
    """
    An address on screen invites "so it can see that network". It
    cannot: the source address of an outbound route says nothing about
    what the interface observes.
    """
    body = get_host(client)
    limitations = " ".join(body["limitations"]).lower()

    assert "not a network scan" in limitations
    assert "not evidence of what it can observe" in limitations


def test_it_is_read_only(client):
    """Identifying the host must not change anything it can be asked twice about."""
    first = get_host(client)
    second = get_host(client)

    assert first["hostname"] == second["hostname"]
    assert first["operating_system"] == second["operating_system"]
    assert first["local_ip"] == second["local_ip"]
