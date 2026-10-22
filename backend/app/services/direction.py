"""
PraHari — which way did a connection go? (§11, ADR-122)

The Traffic view has to say inbound, outbound or local, because a
connection to a service and a connection *from* one mean opposite things
to an operator. Nothing in the canonical schema records it: a
`NormalizedEvent` has `src_ip`/`dst_ip` and two ports, and the Windows
connection table does not report who opened the socket.

So direction here is an **inference**, and it travels with its method
and its evidence the way `DomainAttribution` does. It is never written
to the event, because a stored field reads as something the sensor
observed.

What can actually be concluded
------------------------------
* **Loopback at both ends is a fact**, not an inference: an address in
  127.0.0.0/8 or ::1 at both ends cannot have crossed a network.

* **Port asymmetry is evidence, not proof.** Windows allocates ephemeral
  client ports from 49152-65535. A connection whose local port is
  ephemeral and whose remote port is not was, almost always, opened by
  this host — and the converse for a local service port. "Almost
  always" is why this is reported as an inference with a confidence,
  and why the symmetric cases return `unknown` rather than guessing.

* **It only applies to host-collected records.** On a CSV import or a
  replay, `src_ip` is whichever endpoint the corpus happened to list
  first; it is not "this machine". Calling that outbound would be
  inventing a perspective the data does not have, so every
  non-host-collected record is `unknown` with that stated as the reason.

What is deliberately not attempted
----------------------------------
Reading the listening-port table to resolve the symmetric cases. It
would settle some of them, and it is a second live query against the OS
whose result is a snapshot taken after the connection — a listener that
has since closed, or opened, changes the answer. That is a measurement
this project has not made, so the case stays `unknown`.
"""

from __future__ import annotations

import ipaddress
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

#: Windows' default dynamic client port range. Documented by Microsoft
#: and verifiable with `netsh int ipv4 show dynamicport tcp`; the value
#: is not read from the host, so a machine with a tuned range will
#: produce more `unknown` rather than a wrong answer.
EPHEMERAL_FLOOR = 49152
EPHEMERAL_CEILING = 65535

#: Source types whose records describe THIS host's own sockets, so
#: `src` means "here". Anything else has no local perspective.
HOST_COLLECTED_SOURCE_TYPES = frozenset(
    {
        "windows_connection_table",
        "windows_udp_endpoint",
        "application_layer",
    }
)


class TrafficDirection(str, Enum):
    """Which way a connection went, from this host's point of view."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"
    LOCAL = "local"
    UNKNOWN = "unknown"


class DirectionConfidence(str, Enum):
    """
    Coarse on purpose, mirroring `AttributionConfidence`.

    The evidence does not support finer gradations and a numeric score
    would imply precision this does not have.
    """

    OBSERVED = "observed"   # a fact from the addresses, not an inference
    INFERRED = "inferred"   # port asymmetry; usually right, not certain
    NONE = "none"           # no defensible answer


class DirectionAssessment(BaseModel):
    """A direction, the method that produced it, and what it cannot say."""

    direction: TrafficDirection = TrafficDirection.UNKNOWN
    confidence: DirectionConfidence = DirectionConfidence.NONE
    method: str = Field(
        default="none",
        description="How this was decided, in a word a reader can check.",
    )
    reason: str = Field(
        default="",
        description="Why this answer, in plain words — including why not.",
    )
    limitations: list[str] = Field(default_factory=list)


def _is_loopback(address: Optional[str]) -> bool:
    if not address:
        return False
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def _is_ephemeral(port: Optional[int]) -> bool:
    return port is not None and EPHEMERAL_FLOOR <= port <= EPHEMERAL_CEILING


def assess_direction(
    src_ip: Optional[str],
    dst_ip: Optional[str],
    src_port: Optional[int],
    dst_port: Optional[int],
    source_type: Optional[str],
) -> DirectionAssessment:
    """
    Decide a connection's direction, or decline to.

    Pure and side-effect free: no OS query, no clock, no storage. The
    inputs are exactly what a stored record carries.
    """
    # 1. Loopback at both ends is a property of the addresses.
    if _is_loopback(src_ip) and _is_loopback(dst_ip):
        return DirectionAssessment(
            direction=TrafficDirection.LOCAL,
            confidence=DirectionConfidence.OBSERVED,
            method="loopback_addresses",
            reason=(
                "Both endpoints are loopback addresses, so this connection "
                "did not cross a network."
            ),
        )

    # 2. Without a local perspective there is no "in" or "out".
    if source_type not in HOST_COLLECTED_SOURCE_TYPES:
        return DirectionAssessment(
            direction=TrafficDirection.UNKNOWN,
            confidence=DirectionConfidence.NONE,
            method="no_local_perspective",
            reason=(
                f"This record came from {source_type or 'an unidentified source'}, "
                "which does not describe this host's own sockets. `src` is "
                "whichever endpoint the data listed first, not 'here', so "
                "inbound and outbound have no meaning for it."
            ),
            limitations=[
                "Direction is only inferable for records collected on the host "
                "whose sockets they describe."
            ],
        )

    # 3. Port asymmetry, for host-collected records only.
    src_ephemeral = _is_ephemeral(src_port)
    dst_ephemeral = _is_ephemeral(dst_port)

    shared_limits = [
        "Inferred from the ephemeral port range "
        f"({EPHEMERAL_FLOOR}-{EPHEMERAL_CEILING}), not from observing who "
        "opened the socket. The connection table does not report that.",
        "A service deliberately listening on a high port, or a client bound "
        "to a fixed low port, would be read the wrong way round.",
    ]

    if src_ephemeral and not dst_ephemeral and dst_port is not None:
        return DirectionAssessment(
            direction=TrafficDirection.OUTBOUND,
            confidence=DirectionConfidence.INFERRED,
            method="ephemeral_port_asymmetry",
            reason=(
                f"The local port ({src_port}) is in the ephemeral range and the "
                f"remote port ({dst_port}) is not, which is the shape of a "
                "connection this host opened."
            ),
            limitations=list(shared_limits),
        )

    if dst_ephemeral and not src_ephemeral and src_port is not None:
        return DirectionAssessment(
            direction=TrafficDirection.INBOUND,
            confidence=DirectionConfidence.INFERRED,
            method="ephemeral_port_asymmetry",
            reason=(
                f"The local port ({src_port}) is a service port and the remote "
                f"port ({dst_port}) is ephemeral, which is the shape of a "
                "connection opened towards this host."
            ),
            limitations=list(shared_limits),
        )

    # 4. Symmetric, or missing. Declining is the answer.
    if src_port is None or dst_port is None:
        reason = (
            "One or both ports are absent, so there is no asymmetry to read."
        )
    elif src_ephemeral and dst_ephemeral:
        reason = (
            f"Both ports ({src_port}, {dst_port}) are ephemeral, so neither "
            "end looks like the service."
        )
    else:
        reason = (
            f"Neither port ({src_port}, {dst_port}) is ephemeral, so neither "
            "end looks like the client."
        )

    return DirectionAssessment(
        direction=TrafficDirection.UNKNOWN,
        confidence=DirectionConfidence.NONE,
        method="port_asymmetry_absent",
        reason=reason,
        limitations=[
            "Reading the host's listening-port table would settle some of "
            "these, but that snapshot is taken after the connection and a "
            "listener may have opened or closed since. PraHari has not "
            "made that measurement.",
        ],
    )
