"""
Traffic direction (ADR-122).

Direction is an inference, and the risk is that it stops looking like
one. A column reading "Outbound" beside a connection is read as fact,
so these pin the boundary between what is observed, what is inferred,
and what is declined.
"""

from __future__ import annotations

import pytest

from app.services.direction import (
    DirectionConfidence,
    EPHEMERAL_CEILING,
    EPHEMERAL_FLOOR,
    HOST_COLLECTED_SOURCE_TYPES,
    TrafficDirection,
    assess_direction,
)

HOST = "windows_connection_table"


def test_loopback_at_both_ends_is_observed_not_inferred():
    """
    A property of the addresses. It cannot have crossed a network, and
    no port heuristic is involved — so it is reported as observed.
    """
    got = assess_direction("127.0.0.1", "127.0.0.1", 54321, 5432, HOST)

    assert got.direction is TrafficDirection.LOCAL
    assert got.confidence is DirectionConfidence.OBSERVED
    assert got.method == "loopback_addresses"
    assert got.limitations == [], "a fact from the addresses carries no caveat"


def test_ipv6_loopback_counts_too():
    got = assess_direction("::1", "::1", 54321, 443, HOST)
    assert got.direction is TrafficDirection.LOCAL


def test_an_ephemeral_local_port_reads_as_outbound():
    got = assess_direction("192.168.1.10", "93.184.216.34", 54321, 443, HOST)

    assert got.direction is TrafficDirection.OUTBOUND
    assert got.confidence is DirectionConfidence.INFERRED
    assert "54321" in got.reason and "443" in got.reason
    assert got.limitations, "an inference must carry its caveats"


def test_an_ephemeral_remote_port_reads_as_inbound():
    got = assess_direction("192.168.1.10", "192.168.1.55", 445, 54321, HOST)

    assert got.direction is TrafficDirection.INBOUND
    assert got.confidence is DirectionConfidence.INFERRED


def test_every_inference_states_that_it_did_not_observe_who_opened_the_socket():
    """
    The connection table does not report it. An operator reading
    "Outbound" must be able to find out, from the record itself, that
    this was reasoned rather than seen.
    """
    for src_port, dst_port in ((54321, 443), (445, 54321)):
        got = assess_direction("192.168.1.10", "10.0.0.5", src_port, dst_port, HOST)
        joined = " ".join(got.limitations)
        assert "not from observing who" in joined
        assert "wrong way round" in joined, (
            "the inference must name the case it gets wrong"
        )


@pytest.mark.parametrize(
    ("src_port", "dst_port", "why"),
    [
        (54321, 54322, "Both ports"),
        (443, 80, "Neither port"),
        (None, 443, "absent"),
        (54321, None, "absent"),
    ],
)
def test_a_symmetric_or_incomplete_pair_is_declined(src_port, dst_port, why):
    """
    Declining is an answer. Picking one at random, or defaulting to
    outbound because most traffic is, would be fabrication.
    """
    got = assess_direction("192.168.1.10", "10.0.0.5", src_port, dst_port, HOST)

    assert got.direction is TrafficDirection.UNKNOWN
    assert got.confidence is DirectionConfidence.NONE
    assert why.lower() in got.reason.lower()


@pytest.mark.parametrize(
    "source_type", ["csv_import", "json_stream", "synthetic_replay", None, "unknown"]
)
def test_a_record_with_no_local_perspective_is_declined(source_type):
    """
    On an imported corpus `src_ip` is whichever endpoint the file listed
    first. It is not "this machine", so inbound and outbound have no
    meaning — and the port asymmetry would still have produced a
    confident-looking answer.
    """
    got = assess_direction("192.168.1.10", "93.184.216.34", 54321, 443, source_type)

    assert got.direction is TrafficDirection.UNKNOWN
    assert got.method == "no_local_perspective"
    assert "not 'here'" in got.reason


def test_the_host_source_types_are_the_ones_that_describe_own_sockets():
    # Guards the set itself: widening it silently would start applying a
    # local perspective to data that has none.
    assert "windows_connection_table" in HOST_COLLECTED_SOURCE_TYPES
    assert "csv_import" not in HOST_COLLECTED_SOURCE_TYPES
    assert "json_stream" not in HOST_COLLECTED_SOURCE_TYPES


@pytest.mark.parametrize("port", [EPHEMERAL_FLOOR, EPHEMERAL_CEILING])
def test_the_ephemeral_range_is_inclusive_at_both_ends(port):
    got = assess_direction("192.168.1.10", "10.0.0.5", port, 443, HOST)
    assert got.direction is TrafficDirection.OUTBOUND


@pytest.mark.parametrize("port", [EPHEMERAL_FLOOR - 1, 1024, 80])
def test_a_port_below_the_range_is_not_treated_as_ephemeral(port):
    got = assess_direction("192.168.1.10", "10.0.0.5", 443, port, HOST)
    assert got.direction is not TrafficDirection.INBOUND


def test_a_malformed_address_does_not_raise_or_claim_loopback():
    got = assess_direction("not-an-address", "127.0.0.1", 54321, 443, HOST)
    assert got.direction is not TrafficDirection.LOCAL


def test_loopback_is_decided_before_the_source_type_matters():
    """
    Both ends on loopback is true regardless of who collected it — it
    is read off the addresses, not off a perspective.
    """
    got = assess_direction("127.0.0.1", "127.0.0.1", 54321, 5432, "csv_import")
    assert got.direction is TrafficDirection.LOCAL
    assert got.confidence is DirectionConfidence.OBSERVED
