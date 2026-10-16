"""
PraHari — Telemetry Stream Idempotency, Deduplication & Identity Contract Tests.

Tests the identity contract for /api/v1/stream/ingest/ndjson:
1. Sender-provided stable event IDs (Zeek uid, Suricata/custom event_id)
2. Batch idempotency keys (via body and HTTP header)
3. Safe deduplication on retries (original receipt time and single row preserved)
4. Conflicting event identity reuse (returns HTTP 409 Conflict)
5. In-batch conflict detection and duplicate suppression
6. Preservation of distinct events with identical content
7. Cross-source identity isolation (no cross-source collisions)
8. Partial batch failure recovery and subsequent idempotent retry
9. Concurrency safety under simultaneous duplicate submissions
10. Explicit, preserved legacy behavior for clients without identity metadata
11. Downstream analytics accuracy (source event_count and count_events)

Uses temporary databases only (RFC 5737 documentation IP addresses).
"""

from __future__ import annotations

import concurrent.futures
import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.main import app
from app.schemas.events import DataCategory, TelemetrySource
from app.storage.database import Database

SOURCE_A = "sensor-stream-a"
SOURCE_B = "sensor-stream-b"


@pytest.fixture
def client(tmp_path):
    db_file = str(tmp_path / "idempotency_test.db")
    db = Database(db_path=db_file)
    db.initialize()
    db.upsert_source(
        TelemetrySource(source_id=SOURCE_A, name="Sensor A", source_type="json_stream")
    )
    db.upsert_source(
        TelemetrySource(source_id=SOURCE_B, name="Sensor B", source_type="json_stream")
    )
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as c:
        yield c, db
    app.dependency_overrides.clear()
    db.close()


def _make_ndjson(records: list[dict]) -> str:
    return "\n".join(json.dumps(r) for r in records) + "\n"


# ──────────────────────────────────────────────────────────────────
# 1. Batch Idempotency Keys (Body and Headers)
# ──────────────────────────────────────────────────────────────────


def test_retry_with_batch_idempotency_key_is_deduplicated(client):
    """
    Submitting a batch with an idempotency_key stores the events.
    Re-submitting the exact same batch with the same idempotency_key is an idempotent
    no-op at the storage layer: stored rows and source event_count do not double.
    """
    c, db = client
    records = [
        {
            "ts": 1700000000.0 + i,
            "src_ip": f"192.0.2.{10 + i}",
            "dst_ip": "198.51.100.20",
            "src_port": 40000 + i,
            "dst_port": 443,
            "proto": "tcp",
            "bytes_total": 500,
        }
        for i in range(3)
    ]
    payload = {
        "source_id": SOURCE_A,
        "ndjson_content": _make_ndjson(records),
        "idempotency_key": "batch-2026-001",
    }

    # First attempt: initial write
    res1 = c.post("/api/v1/stream/ingest/ndjson", json=payload)
    assert res1.status_code == 200, res1.text
    summary1 = res1.json()
    assert summary1["accepted_records"] == 3
    assert summary1["rejected_records"] == 0

    events_first = db.list_events(source_id=SOURCE_A, limit=10)
    assert len(events_first) == 3
    source_first = db.get_source(SOURCE_A)
    assert source_first.event_count == 3
    first_receipts = {e.event_id: e.received_at for e in events_first}

    # Second attempt: network retry after timeout
    res2 = c.post("/api/v1/stream/ingest/ndjson", json=payload)
    assert res2.status_code == 200, res2.text
    summary2 = res2.json()
    assert summary2["accepted_records"] == 3
    assert summary2["rejected_records"] == 0

    events_second = db.list_events(source_id=SOURCE_A, limit=10)
    assert len(events_second) == 3, "retry must not insert duplicate rows"
    source_second = db.get_source(SOURCE_A)
    assert source_second.event_count == 3, "source event_count must not inflate"

    # Preserves original receipt timestamps (ADR-048)
    for event in events_second:
        assert event.received_at == first_receipts[event.event_id], "original receipt must not be rewritten"


def test_retry_via_idempotency_key_header(client):
    """
    Idempotency key supplied via the standard 'Idempotency-Key' HTTP header
    behaves identically to one provided in the request body.
    """
    c, db = client
    records = [
        {
            "ts": 1700000100.0,
            "src_ip": "192.0.2.55",
            "dst_ip": "198.51.100.55",
            "src_port": 51234,
            "dst_port": 80,
            "proto": "tcp",
        }
    ]
    payload = {
        "source_id": SOURCE_A,
        "ndjson_content": _make_ndjson(records),
    }
    headers = {"Idempotency-Key": "batch-hdr-alpha"}

    # Attempt 1
    r1 = c.post("/api/v1/stream/ingest/ndjson", json=payload, headers=headers)
    assert r1.status_code == 200
    assert db.count_events(source_id=SOURCE_A) == 1

    # Attempt 2 (Retry)
    r2 = c.post("/api/v1/stream/ingest/ndjson", json=payload, headers=headers)
    assert r2.status_code == 200
    assert db.count_events(source_id=SOURCE_A) == 1


# ──────────────────────────────────────────────────────────────────
# 2. Sender-Provided Stable Event IDs (Zeek UID, Suricata / Custom ID)
# ──────────────────────────────────────────────────────────────────


def test_retry_with_zeek_uid_is_deduplicated(client):
    """
    Zeek records carry a connection UID ('uid'). The adapter extracts this
    and derives a deterministic, source-scoped event identity. Retrying
    Zeek records deduplicates cleanly even without a batch idempotency key.
    """
    c, db = client
    zeek_records = [
        {
            "ts": 1700000200.0,
            "uid": "C6p1om3JySFOCU7Dhh",
            "id.orig_h": "192.0.2.30",
            "id.orig_p": 45000,
            "id.resp_h": "198.51.100.30",
            "id.resp_p": 443,
            "proto": "tcp",
            "orig_bytes": 100,
            "resp_bytes": 200,
        },
        {
            "ts": 1700000201.0,
            "uid": "C99999999999999999",
            "id.orig_h": "192.0.2.31",
            "id.orig_p": 45001,
            "id.resp_h": "198.51.100.30",
            "id.resp_p": 443,
            "proto": "tcp",
            "orig_bytes": 150,
            "resp_bytes": 300,
        },
    ]
    payload = {
        "source_id": SOURCE_A,
        "ndjson_content": _make_ndjson(zeek_records),
    }

    # Initial submission
    res1 = c.post("/api/v1/stream/ingest/ndjson", json=payload)
    assert res1.status_code == 200
    assert db.count_events(source_id=SOURCE_A) == 2

    # Retry submission
    res2 = c.post("/api/v1/stream/ingest/ndjson", json=payload)
    assert res2.status_code == 200
    assert db.count_events(source_id=SOURCE_A) == 2


def test_retry_with_explicit_event_id_field(client):
    """Explicit 'event_id' field in raw record provides deterministic identity."""
    c, db = client
    record = {
        "ts": 1700000300.0,
        "event_id": "sensor-flow-987654",
        "src_ip": "192.0.2.80",
        "dst_ip": "198.51.100.80",
        "src_port": 33333,
        "dst_port": 53,
        "proto": "udp",
    }
    payload = {
        "source_id": SOURCE_A,
        "ndjson_content": _make_ndjson([record]),
    }

    c.post("/api/v1/stream/ingest/ndjson", json=payload)
    c.post("/api/v1/stream/ingest/ndjson", json=payload)
    assert db.count_events(source_id=SOURCE_A) == 1


# ──────────────────────────────────────────────────────────────────
# 3. Legitimate Distinct Events With Identical Content
# ──────────────────────────────────────────────────────────────────


def test_identical_content_distinct_events_are_preserved(client):
    """
    Crucial contract requirement: identical content must NOT be assumed to be
    the same logical event. Two distinct flows with identical 5-tuples and timestamps
    in the same batch must both be stored and never collapsed.
    """
    c, db = client
    # Two identical connection records in the same batch
    identical_flow = {
        "ts": 1700000400.0,
        "src_ip": "192.0.2.90",
        "dst_ip": "198.51.100.90",
        "src_port": 50000,
        "dst_port": 80,
        "proto": "tcp",
    }
    records = [identical_flow, identical_flow]
    payload = {
        "source_id": SOURCE_A,
        "ndjson_content": _make_ndjson(records),
        "idempotency_key": "batch-duplicate-content-ok",
    }

    res = c.post("/api/v1/stream/ingest/ndjson", json=payload)
    assert res.status_code == 200
    summary = res.json()
    assert summary["accepted_records"] == 2
    assert summary["rejected_records"] == 0

    stored = db.list_events(source_id=SOURCE_A, limit=10)
    assert len(stored) == 2, "legitimate distinct events must not be silently merged"
    assert stored[0].event_id != stored[1].event_id


# ──────────────────────────────────────────────────────────────────
# 4. Conflicting Identity Reuse Handling
# ──────────────────────────────────────────────────────────────────


def test_conflicting_id_reuse_across_requests_returns_409(client):
    """
    If a sender reuses an idempotency key or event ID with conflicting telemetry
    content, the backend must reject it explicitly with HTTP 409 Conflict rather
    than silently overwriting or merging.
    """
    c, db = client
    record_initial = {
        "ts": 1700000500.0,
        "event_id": "flow-fixed-id-001",
        "src_ip": "192.0.2.1",
        "dst_ip": "198.51.100.1",
        "src_port": 1000,
        "dst_port": 80,
        "proto": "tcp",
    }
    c.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SOURCE_A, "ndjson_content": _make_ndjson([record_initial])},
    )

    # Reusing the same event_id with DIFFERENT IP addresses (conflict)
    record_conflicting = {
        "ts": 1700000500.0,
        "event_id": "flow-fixed-id-001",
        "src_ip": "203.0.113.99",
        "dst_ip": "198.51.100.1",
        "src_port": 1000,
        "dst_port": 80,
        "proto": "tcp",
    }
    res_conflict = c.post(
        "/api/v1/stream/ingest/ndjson",
        json={"source_id": SOURCE_A, "ndjson_content": _make_ndjson([record_conflicting])},
    )
    assert res_conflict.status_code == 409, res_conflict.text
    detail = res_conflict.json()["detail"]
    assert detail["error"] == "event_identity_conflict"

    # Verify original telemetry was preserved and not corrupted
    event = db.list_events(source_id=SOURCE_A)[0]
    assert event.src_ip == "192.0.2.1"


def test_intra_batch_conflicting_event_id_is_rejected(client):
    """
    If a single batch contains multiple records sharing the same event_id
    but with conflicting content, the conflicting record is rejected.
    """
    c, db = client
    line1 = {
        "ts": 1700000600.0,
        "event_id": "batch-conflict-01",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.10",
        "src_port": 1000,
        "dst_port": 80,
        "proto": "tcp",
    }
    line2 = {
        "ts": 1700000600.0,
        "event_id": "batch-conflict-01",
        "src_ip": "192.0.2.99",  # conflicting src_ip
        "dst_ip": "198.51.100.10",
        "src_port": 1000,
        "dst_port": 80,
        "proto": "tcp",
    }
    payload = {
        "source_id": SOURCE_A,
        "ndjson_content": _make_ndjson([line1, line2]),
    }
    res = c.post("/api/v1/stream/ingest/ndjson", json=payload)
    assert res.status_code == 200
    summary = res.json()
    assert summary["total_records"] == 2
    assert summary["accepted_records"] == 1
    assert summary["rejected_records"] == 1
    assert summary["rejection_reasons"]["conflicting_event_id"] == 1
    assert db.count_events(source_id=SOURCE_A) == 1


def test_intra_batch_exact_duplicate_is_suppressed(client):
    """
    If a single batch contains multiple identical records sharing the same explicit event_id,
    the duplicate is suppressed and only one copy persisted.
    """
    c, db = client
    line = {
        "ts": 1700000650.0,
        "event_id": "batch-dup-01",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.10",
        "src_port": 1000,
        "dst_port": 80,
        "proto": "tcp",
    }
    payload = {
        "source_id": SOURCE_A,
        "ndjson_content": _make_ndjson([line, line]),
    }
    res = c.post("/api/v1/stream/ingest/ndjson", json=payload)
    assert res.status_code == 200
    summary = res.json()
    assert summary["total_records"] == 2
    assert summary["accepted_records"] == 1
    assert summary["rejected_records"] == 1
    assert summary["rejection_reasons"]["duplicate_event_in_batch"] == 1
    assert db.count_events(source_id=SOURCE_A) == 1


# ──────────────────────────────────────────────────────────────────
# 5. Cross-Source Identity Scoping
# ──────────────────────────────────────────────────────────────────


def test_cross_source_isolation_no_collisions(client):
    """
    Two different sources submitting the same sender event_id or batch key
    must be strictly isolated by source_id. They must not collide or conflict.
    """
    c, db = client
    # Source A submits event "flow-001"
    c.post(
        "/api/v1/stream/ingest/ndjson",
        json={
            "source_id": SOURCE_A,
            "ndjson_content": _make_ndjson([
                {
                    "ts": 1700000700.0,
                    "event_id": "flow-001",
                    "src_ip": "192.0.2.1",
                    "dst_ip": "198.51.100.1",
                    "src_port": 1111,
                    "dst_port": 80,
                    "proto": "tcp",
                }
            ]),
        },
    )

    # Source B submits event with identical event_id "flow-001" but different endpoints
    res_b = c.post(
        "/api/v1/stream/ingest/ndjson",
        json={
            "source_id": SOURCE_B,
            "ndjson_content": _make_ndjson([
                {
                    "ts": 1700000700.0,
                    "event_id": "flow-001",
                    "src_ip": "192.0.2.222",
                    "dst_ip": "198.51.100.222",
                    "src_port": 2222,
                    "dst_port": 443,
                    "proto": "tcp",
                }
            ]),
        },
    )
    assert res_b.status_code == 200, "sources must be strictly isolated"
    assert db.count_events(source_id=SOURCE_A) == 1
    assert db.count_events(source_id=SOURCE_B) == 1
    assert db.count_events() == 2


# ──────────────────────────────────────────────────────────────────
# 6. Legacy Clients Without Identity Metadata
# ──────────────────────────────────────────────────────────────────


def test_legacy_clients_without_identity_metadata_remain_unmodified(client):
    """
    Existing clients without identity metadata retain explicit, documented behavior
    (per ADR-048 and test_the_stream_path_is_not_idempotent_on_retry).
    The backend does not guess or assume identical content means a duplicate.
    """
    c, db = client
    records = [
        {
            "ts": 1700000800.0,
            "id.orig_h": "192.0.2.15",
            "id.resp_h": "198.51.100.15",
            "id.orig_p": 4444,
            "id.resp_p": 80,
            "proto": "tcp",
        }
    ]
    payload = {
        "source_id": SOURCE_A,
        "ndjson_content": _make_ndjson(records),
        # Note: no idempotency_key, and record has no uid or event_id
    }

    c.post("/api/v1/stream/ingest/ndjson", json=payload)
    c.post("/api/v1/stream/ingest/ndjson", json=payload)

    # Preserves legacy behavior: 2 distinct events stored
    assert db.count_events(source_id=SOURCE_A) == 2


# ──────────────────────────────────────────────────────────────────
# 7. Partial Batch Failures & Retry
# ──────────────────────────────────────────────────────────────────


def test_partial_batch_failure_and_retry(client):
    """
    A batch containing malformed lines persists the valid lines and reports the
    rejections. A subsequent retry of the entire batch is idempotent on the valid lines.
    """
    c, db = client
    lines = [
        json.dumps({
            "ts": 1700000900.0,
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1",
            "src_port": 1000,
            "dst_port": 80,
            "proto": "tcp",
        }),
        "THIS_IS_CORRUPT_JSON_DATA",
        json.dumps({
            "ts": 1700000901.0,
            "src_ip": "192.0.2.2",
            "dst_ip": "198.51.100.2",
            "src_port": 2000,
            "dst_port": 80,
            "proto": "tcp",
        }),
    ]
    payload = {
        "source_id": SOURCE_A,
        "ndjson_content": "\n".join(lines),
        "idempotency_key": "batch-partial-test",
    }

    # Attempt 1
    r1 = c.post("/api/v1/stream/ingest/ndjson", json=payload)
    assert r1.status_code == 200
    s1 = r1.json()
    assert s1["total_records"] == 3
    assert s1["accepted_records"] == 2
    assert s1["rejected_records"] == 1
    assert db.count_events(source_id=SOURCE_A) == 2

    # Attempt 2 (Retry of the entire batch)
    r2 = c.post("/api/v1/stream/ingest/ndjson", json=payload)
    assert r2.status_code == 200
    s2 = r2.json()
    assert s2["total_records"] == 3
    assert s2["accepted_records"] == 2
    assert s2["rejected_records"] == 1
    # Storage count remains 2 (no duplicate insertion on retry)
    assert db.count_events(source_id=SOURCE_A) == 2


# ──────────────────────────────────────────────────────────────────
# 8. Concurrency Safety
# ──────────────────────────────────────────────────────────────────


def test_concurrent_duplicate_submissions(client):
    """
    Simultaneous concurrent requests of the same batch with idempotency_key
    must execute cleanly without deadlocks or duplicated rows.
    """
    c, db = client
    records = [
        {
            "ts": 1700001000.0 + i,
            "src_ip": f"192.0.2.{i}",
            "dst_ip": "198.51.100.1",
            "src_port": 10000 + i,
            "dst_port": 443,
            "proto": "tcp",
        }
        for i in range(5)
    ]
    payload = {
        "source_id": SOURCE_A,
        "ndjson_content": _make_ndjson(records),
        "idempotency_key": "concurrent-batch-key-01",
    }

    def _submit():
        return c.post("/api/v1/stream/ingest/ndjson", json=payload)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(_submit) for _ in range(4)]
        results = [f.result() for f in futures]

    for res in results:
        assert res.status_code == 200

    # Must have stored exactly 5 events, never 10, 15, or 20
    assert db.count_events(source_id=SOURCE_A) == 5
    source = db.get_source(SOURCE_A)
    assert source.event_count == 5


# ──────────────────────────────────────────────────────────────────
# 9. Downstream Analytics & Aggregation
# ──────────────────────────────────────────────────────────────────


def test_downstream_analytics_and_counts_remain_truthful_after_retries(client):
    """
    Downstream metrics (event_count, count_events, list_events) must
    reflect truthful counts without inflation caused by retries.
    """
    c, db = client
    records = [
        {
            "ts": 1700001100.0 + i,
            "src_ip": f"192.0.2.{i}",
            "dst_ip": "198.51.100.10",
            "src_port": 20000 + i,
            "dst_port": 80,
            "proto": "tcp",
            "bytes_total": 1000,
        }
        for i in range(4)
    ]
    payload = {
        "source_id": SOURCE_A,
        "ndjson_content": _make_ndjson(records),
        "idempotency_key": "analytics-check-batch",
    }

    # Ingest then retry 3 times
    for _ in range(4):
        res = c.post("/api/v1/stream/ingest/ndjson", json=payload)
        assert res.status_code == 200

    # Total events count
    total_db = db.count_events(source_id=SOURCE_A)
    assert total_db == 4

    # Source record event_count
    source = db.get_source(SOURCE_A)
    assert source.event_count == 4

    # Pagination count
    listed = db.list_events(source_id=SOURCE_A, limit=50)
    assert len(listed) == 4


# ──────────────────────────────────────────────────────────────────
# 12. Canonical identity-conflict policy (ADR-050)
#
# The first conflict check compared only source, time and the
# five-tuple. Every other field — byte counts, packet counts, the
# label, the event type — could be changed under a re-used identity
# and was silently discarded while the API returned HTTP 200 and
# reported the record as accepted. These pin the whole policy.
# ──────────────────────────────────────────────────────────────────

_MATERIAL_BASE = {
    "event_id": "evt-material-baseline",
    "timestamp": "2026-01-01T00:00:00Z",
    "src_ip": "192.0.2.10",
    "dst_ip": "198.51.100.20",
    "src_port": 4444,
    "dst_port": 443,
    "proto": "tcp",
    "bytes": 100,
    "packets": 2,
    "duration": 1.5,
}


def _post(c, records, source_id=SOURCE_A, **extra):
    body = {
        "source_id": source_id,
        "ndjson_content": _make_ndjson(records),
        **extra,
    }
    return c.post("/api/v1/stream/ingest/ndjson", json=body)


def _audit_actions(db):
    with db.get_connection() as conn:
        return [r["action"] for r in conn.execute("SELECT action FROM audit_events")]


@pytest.mark.parametrize(
    "field_name, mutation",
    [
        ("bytes_total", {"bytes": 999999}),
        ("packets", {"packets": 50000}),
        ("duration", {"duration": 987.0}),
        ("event_type", {"event_type": "alert", "alert": {"signature": "ET SCAN"}}),
        ("label", {"label": "DDoS"}),
        ("dst_port", {"dst_port": 8080}),
    ],
)
def test_reusing_an_identity_with_changed_material_content_is_a_conflict(
    client, field_name, mutation
):
    """
    Each of these fields is read by feature extraction, labelling or both.
    Changing one under an identity that is already taken is a different
    claim about the world, not a retry.
    """
    c, db = client
    assert _post(c, [_MATERIAL_BASE]).status_code == 200

    response = _post(c, [{**_MATERIAL_BASE, **mutation}])

    assert response.status_code == 409, (
        "changing " + field_name + " under a reused event_id was accepted silently"
    )
    detail = response.json()["detail"]
    assert detail["error"] == "event_identity_conflict"
    assert field_name in detail["message"], (
        "the 409 does not name the conflicting field: " + detail["message"]
    )


def test_a_conflict_leaves_the_stored_event_exactly_as_it_was(client):
    """A refused submission must not partially mutate the original."""
    c, db = client
    assert _post(c, [_MATERIAL_BASE]).status_code == 200

    conflicting = {**_MATERIAL_BASE, "bytes": 999999, "label": "DDoS"}
    assert _post(c, [conflicting]).status_code == 409

    assert db.count_events() == 1
    stored = db.list_events(limit=5)[0]
    assert stored.bytes_total == 100
    assert stored.packets == 2
    assert stored.duration == 1.5
    assert stored.label is None


def test_a_conflict_rolls_back_the_entire_batch(client):
    """
    get_connection rolls back on any exception, so a conflict anywhere in
    the batch discards the whole batch — including records that would
    otherwise have been written.
    """
    c, db = client
    assert _post(c, [_MATERIAL_BASE]).status_code == 200
    before = db.count_events()

    good = {**_MATERIAL_BASE, "event_id": "evt-would-have-been-fine", "src_port": 5555}
    conflicting = {**_MATERIAL_BASE, "bytes": 42}

    assert _post(c, [good, conflicting]).status_code == 409

    assert db.count_events() == before, "a rejected batch left partial rows behind"


def test_a_conflict_is_recorded_in_the_audit_log(client):
    """A refusal that leaves no trace is indistinguishable from no request."""
    c, db = client
    assert _post(c, [_MATERIAL_BASE]).status_code == 200
    assert _post(c, [{**_MATERIAL_BASE, "bytes": 1}]).status_code == 409

    assert "ingest_ndjson_stream_conflict" in _audit_actions(db)


def test_excluded_fields_do_not_manufacture_false_conflicts(client):
    """
    raw_reference encodes the record's POSITION in the batch and is
    deliberately excluded. The same event resent at a different position
    is still the same event, not a conflict.
    """
    c, db = client
    other = {**_MATERIAL_BASE, "event_id": "evt-other", "src_port": 6000}

    assert _post(c, [_MATERIAL_BASE, other]).status_code == 200
    # Same two events, positions swapped.
    response = _post(c, [other, _MATERIAL_BASE])

    assert response.status_code == 200
    assert db.count_events() == 2
    assert response.json()["stored_records"] == 0
    assert response.json()["duplicate_records"] == 2


# ──────────────────────────────────────────────────────────────────
# 13. The response distinguishes stored from duplicate (ADR-050)
# ──────────────────────────────────────────────────────────────────

def test_the_summary_separates_what_was_stored_from_what_merely_parsed(client):
    """
    accepted_records counts what PARSED. A retry parses perfectly and
    stores nothing, and previously reported the same number either way.
    """
    c, db = client
    records = [
        {**_MATERIAL_BASE, "event_id": "evt-sep-" + str(i), "src_port": 7000 + i}
        for i in range(3)
    ]

    first = _post(c, records).json()
    assert first["accepted_records"] == 3
    assert first["stored_records"] == 3
    assert first["duplicate_records"] == 0

    retry = _post(c, records).json()
    assert retry["accepted_records"] == 3, "parsing is unchanged on a retry"
    assert retry["stored_records"] == 0, "a retry must not claim to have stored rows"
    assert retry["duplicate_records"] == 3
    assert db.count_events() == 3


def test_a_partial_retry_reports_the_mixture(client):
    """Two already-present records and one new one in a single batch."""
    c, db = client
    known = [
        {**_MATERIAL_BASE, "event_id": "evt-mix-" + str(i), "src_port": 7100 + i}
        for i in range(2)
    ]
    assert _post(c, known).status_code == 200

    fresh = {**_MATERIAL_BASE, "event_id": "evt-mix-new", "src_port": 7199}
    body = _post(c, known + [fresh]).json()

    assert body["accepted_records"] == 3
    assert body["stored_records"] == 1
    assert body["duplicate_records"] == 2
    assert db.count_events() == 3


def test_legacy_clients_still_receive_a_coherent_summary(client):
    """
    A client sending no identity metadata gets a fresh uuid4 per record —
    documented legacy behaviour — so every record stores and none is a
    duplicate, however many times it retries.
    """
    c, db = client
    record = {
        "timestamp": "2026-01-01T00:00:00Z",
        "src_ip": "192.0.2.77",
        "dst_ip": "198.51.100.88",
        "src_port": 1234,
        "dst_port": 80,
        "proto": "tcp",
    }
    first = _post(c, [record]).json()
    second = _post(c, [record]).json()

    assert first["stored_records"] == 1 and first["duplicate_records"] == 0
    assert second["stored_records"] == 1 and second["duplicate_records"] == 0
    assert db.count_events() == 2, (
        "legacy behaviour is unchanged: without identity metadata a retry "
        "double-counts, which is exactly why the protocol fields exist"
    )


# ──────────────────────────────────────────────────────────────────
# 14. What a batch idempotency key does and does not bind (ADR-050)
# ──────────────────────────────────────────────────────────────────

def _keyed(c, records, key, source_id=SOURCE_A):
    return _post(c, records, source_id=source_id, idempotency_key=key)


def _batch(n, start=0):
    return [
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1",
            "src_port": 9000 + i,
            "dst_port": 443,
            "proto": "tcp",
            "bytes": 10 * (i + 1),
        }
        for i in range(start, start + n)
    ]


def test_batch_key_identical_retry_stores_nothing_new(client):
    c, db = client
    records = _batch(3)
    assert _keyed(c, records, "k-same").json()["stored_records"] == 3
    retry = _keyed(c, records, "k-same").json()
    assert retry["stored_records"] == 0 and retry["duplicate_records"] == 3
    assert db.count_events() == 3


def test_batch_key_reused_with_changed_content_at_a_position_conflicts(client):
    """
    The key binds (key, record index) to an identity. Changing what sits
    at that index is caught by the canonical comparison, not by the key.
    """
    c, db = client
    records = _batch(3)
    assert _keyed(c, records, "k-mut").status_code == 200

    mutated = [dict(r) for r in records]
    mutated[1]["bytes"] = 123456

    response = _keyed(c, mutated, "k-mut")
    assert response.status_code == 409
    assert "bytes_total" in response.json()["detail"]["message"]
    assert db.count_events() == 3


def test_batch_key_reused_with_reordered_records_conflicts(client):
    """Reordering moves content to a different index, so identities clash."""
    c, db = client
    records = _batch(3)
    assert _keyed(c, records, "k-order").status_code == 200

    assert _keyed(c, list(reversed(records)), "k-order").status_code == 409
    assert db.count_events() == 3


def test_batch_key_reused_with_a_shorter_batch_stores_nothing_new(client):
    """
    A truncated retry is indistinguishable from a retry of a prefix. The
    key does NOT detect the missing tail — a documented boundary.
    """
    c, db = client
    records = _batch(3)
    assert _keyed(c, records, "k-short").status_code == 200

    response = _keyed(c, records[:2], "k-short")
    assert response.status_code == 200
    assert response.json()["stored_records"] == 0
    assert db.count_events() == 3, "the dropped record is NOT removed, and is not flagged"


def test_batch_key_reused_with_a_longer_batch_appends_the_tail(client):
    """
    Extra records occupy fresh indices and are stored. The key guarantees
    nothing about the batch as a whole — only about (key, index).
    """
    c, db = client
    records = _batch(3)
    assert _keyed(c, records, "k-long").status_code == 200

    response = _keyed(c, records + _batch(2, start=3), "k-long")
    assert response.status_code == 200
    assert response.json()["stored_records"] == 2
    assert response.json()["duplicate_records"] == 3
    assert db.count_events() == 5


def test_the_same_batch_key_under_two_sources_does_not_collide(client):
    c, db = client
    records = _batch(2)
    assert _keyed(c, records, "k-shared", source_id=SOURCE_A).json()["stored_records"] == 2
    assert _keyed(c, records, "k-shared", source_id=SOURCE_B).json()["stored_records"] == 2
    assert db.count_events() == 4


def test_a_lost_response_followed_by_a_retry_stores_one_copy(client):
    """
    The case the protocol exists for: the write succeeded, the client
    never saw the 200, and retries.
    """
    c, db = client
    records = _batch(4)
    first = _keyed(c, records, "k-lost")
    assert first.status_code == 200 and first.json()["stored_records"] == 4

    # The client saw nothing and resends the identical batch.
    retry = _keyed(c, records, "k-lost")
    assert retry.status_code == 200
    assert retry.json()["stored_records"] == 0
    assert db.count_events() == 4
