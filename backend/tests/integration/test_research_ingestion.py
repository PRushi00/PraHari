"""
Research-corpus ingestion: isolation, units, timestamps, identity, manifest.

Every fixture here is a few synthetic rows written by the test. No real
benchmark file is used, downloaded or referenced.

The failures these guard against all share a shape: the import *succeeds*
and produces a plausible number that is wrong. A 10^6x duration error, a
date read with day and month swapped, a repeated header counted as an
attack — none of them raises anything.

Documentation addresses only (RFC 5737).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.adapters.research_csv import (
    DurationUnit,
    ImportQuality,
    ResearchCsvPolicy,
    TimestampFormat,
    deterministic_event_id,
    import_research_csv,
    looks_like_header_row,
    parse_numeric,
    parse_timestamp,
    sha256_bytes,
    sha256_file,
)
from app.api.deps import get_db
from app.api.v1.research_import import get_research_db, reset_research_db
from app.core.config import AppConfig, get_config
from app.core.research_store import (
    ResearchDatabaseCollision,
    ResearchDatabaseInvalid,
    ResearchDatabaseNotConfigured,
    is_operational_database,
    resolve_research_database,
)
from app.main import app
from app.research.import_manifest import build_manifest, load_manifest, save_manifest
from app.schemas.events import LabelProvenance, QualityFlag
from app.storage.database import Database

HEADER = (
    "Timestamp,Src IP,Dst IP,Src Port,Dst Port,Protocol,Flow Duration,"
    "Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,TotLen Bwd Pkts,Label"
)


def _row(ts="2018-02-14 10:32:00", dur="2500000", fwd_p="10", bwd_p="7",
         fwd_b="1000", bwd_b="500", label="Benign", sport="40000"):
    return (
        f"{ts},192.0.2.10,198.51.100.20,{sport},443,6,{dur},"
        f"{fwd_p},{bwd_p},{fwd_b},{bwd_b},{label}"
    )


def _csv(*rows: str) -> str:
    return "\n".join([HEADER, *rows]) + "\n"


def _policy(**kw) -> ResearchCsvPolicy:
    defaults = dict(
        timestamp_format=TimestampFormat.ISO,
        duration_unit=DurationUnit.MICROSECONDS,
    )
    defaults.update(kw)
    return ResearchCsvPolicy(**defaults)


def _import(csv_text: str, policy=None, digest="a" * 64):
    return import_research_csv(
        csv_text=csv_text,
        source_id="corpus",
        source_sha256=digest,
        policy=policy or _policy(),
    )


# ──────────────────────────────────────────────────────────────────
# 1–3. Research database isolation (fail closed)
# ──────────────────────────────────────────────────────────────────


def test_missing_research_database_configuration_is_refused():
    config = AppConfig(research_database_url="")
    with pytest.raises(ResearchDatabaseNotConfigured) as exc:
        resolve_research_database(config)
    assert "will not fall back" in str(exc.value).lower()


def test_research_database_pointing_at_the_operational_one_is_refused():
    """
    The single accident worth engineering against: a bulk benchmark import
    landing in the operator's only copy of genuine local telemetry.
    """
    config = AppConfig(
        database_url="sqlite:///./prahari.db",
        research_database_url="sqlite:///./prahari.db",
    )
    with pytest.raises(ResearchDatabaseCollision) as exc:
        resolve_research_database(config)
    assert "operational" in str(exc.value).lower()


def test_collision_is_detected_through_path_indirection():
    """`./a/../prahari.db` is the operational database by another spelling."""
    config = AppConfig(
        database_url="sqlite:///./prahari.db",
        research_database_url="sqlite:///./backend/../prahari.db",
    )
    with pytest.raises(ResearchDatabaseCollision):
        resolve_research_database(config)


def test_legacy_backend_database_also_counts_as_operational():
    config = AppConfig(research_database_url="sqlite:///./backend/prahari.db")
    with pytest.raises(ResearchDatabaseCollision):
        resolve_research_database(config)


def test_unsupported_url_scheme_is_refused_not_guessed():
    config = AppConfig(research_database_url="postgresql://host/db")
    with pytest.raises(ResearchDatabaseInvalid):
        resolve_research_database(config)


def test_missing_parent_directory_is_refused(tmp_path):
    config = AppConfig(
        research_database_url=f"sqlite:///{tmp_path / 'nope' / 'r.db'}"
    )
    with pytest.raises(ResearchDatabaseInvalid) as exc:
        resolve_research_database(config)
    assert "does not exist" in str(exc.value)


def test_a_configured_temporary_research_database_resolves(tmp_path):
    target = tmp_path / "research.db"
    config = AppConfig(research_database_url=f"sqlite:///{target}")
    resolved = resolve_research_database(config)
    assert resolved == target.resolve()
    assert not is_operational_database(resolved, config)


def test_operational_database_recognition():
    config = AppConfig(database_url="sqlite:///./prahari.db")
    assert is_operational_database(config.get_database_path(), config) is True
    assert is_operational_database("/tmp/somewhere-else.db", config) is False


# ──────────────────────────────────────────────────────────────────
# 4–5. Duration units
# ──────────────────────────────────────────────────────────────────


def test_microseconds_are_converted_to_seconds():
    """CICFlowMeter Flow Duration is microseconds; the schema is seconds."""
    events, quality = _import(_csv(_row(dur="2500000")))
    assert quality.accepted == 1
    assert events[0].duration == pytest.approx(2.5)


def test_duration_is_not_imported_when_the_unit_is_undeclared():
    """
    Refusing to import beats importing a 10^6x error. Nothing downstream
    could detect the difference between 2.5 s and 2,500,000 s.
    """
    events, quality = _import(
        _csv(_row(dur="2500000")), policy=_policy(duration_unit=DurationUnit.UNKNOWN)
    )
    assert events[0].duration is None
    assert any("duration_unit" in w for w in quality.warnings)


def test_a_source_already_in_seconds_is_left_alone():
    events, _ = _import(
        _csv(_row(dur="2.5")), policy=_policy(duration_unit=DurationUnit.SECONDS)
    )
    assert events[0].duration == pytest.approx(2.5)


def test_the_zeek_adapter_still_reports_seconds_unchanged():
    """Regression: the conversion must not reach adapters already in seconds."""
    from app.adapters.json_stream import JsonStreamAdapter

    result = JsonStreamAdapter(adapter_id="zeek").validate_and_normalize(
        {
            "ts": 1700000000.0,
            "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.1",
            "id.orig_p": 1, "id.resp_p": 2, "proto": "tcp",
            "duration": 2.5,
        },
        record_index=0,
    )
    assert result.event.duration == pytest.approx(2.5)


# ──────────────────────────────────────────────────────────────────
# 6. Timestamps
# ──────────────────────────────────────────────────────────────────


def test_an_ambiguous_date_is_rejected_rather_than_guessed():
    """
    02/03/2018 is 2 March or 3 February. Choosing silently reorders the
    dataset, and chronological order is what the entire protocol rests on.
    """
    parsed, reason, _ = parse_timestamp("02/03/2018 10:00:00", ResearchCsvPolicy())
    assert parsed is None
    assert reason == "ambiguous_date_format"


def test_an_ambiguous_date_parses_once_the_format_is_declared():
    day_first, _, _ = parse_timestamp(
        "02/03/2018 10:00:00",
        ResearchCsvPolicy(timestamp_format=TimestampFormat.DAY_FIRST),
    )
    month_first, _, _ = parse_timestamp(
        "02/03/2018 10:00:00",
        ResearchCsvPolicy(timestamp_format=TimestampFormat.MONTH_FIRST),
    )
    assert (day_first.month, day_first.day) == (3, 2)
    assert (month_first.month, month_first.day) == (2, 3)
    assert day_first != month_first


def test_an_unambiguous_slash_date_is_accepted_under_auto():
    parsed, reason, _ = parse_timestamp("25/02/2018 10:00:00", ResearchCsvPolicy())
    assert reason is None
    assert (parsed.day, parsed.month) == (25, 2)


def test_unknown_source_timezone_is_recorded_not_invented():
    _, _, warnings = parse_timestamp("2018-02-14 10:32:00", _policy())
    assert any("timezone_unknown" in w for w in warnings)


def test_a_timezone_aware_input_is_respected():
    parsed, _, warnings = parse_timestamp("2018-02-14T10:32:00+05:30", _policy())
    assert parsed.hour == 5 and parsed.minute == 2
    assert not any("unknown" in w for w in warnings)


def test_an_unparseable_timestamp_is_rejected_with_a_reason():
    _, reason, _ = parse_timestamp("not-a-date", _policy())
    assert reason == "unparseable_timestamp"
    events, quality = _import(_csv(_row(ts="not-a-date")))
    assert events == []
    assert quality.rejection_reasons["unparseable_timestamp"] == 1


def test_naive_timestamps_are_flagged_on_the_event():
    events, _ = _import(_csv(_row()))
    assert QualityFlag.TIMESTAMP_UNCERTAINTY in events[0].quality_flags


# ──────────────────────────────────────────────────────────────────
# 7–8. Repeated headers
# ──────────────────────────────────────────────────────────────────


def test_a_repeated_header_row_is_detected():
    header = HEADER.split(",")
    row = dict(zip(header, header))
    assert looks_like_header_row(row, header) is True


def test_a_repeated_header_is_skipped_and_never_becomes_an_attack():
    """
    CSE-CIC-IDS2018 CSVs are documented to contain embedded header lines.
    Normalising one yields label="Label", which the attack rule ("anything
    not benign") would score as an incident — fabricated positives in the
    target.
    """
    events, quality = _import(_csv(_row(), HEADER, _row(sport="40001")))

    assert quality.skipped_header_rows == 1
    assert quality.accepted == 2
    assert all(e.label != "Label" for e in events)
    assert not any(
        e.label and e.label.strip().lower() not in ("benign", "") for e in events
    )


def test_a_genuine_row_resembling_a_header_is_not_silently_lost():
    events, quality = _import(_csv(_row(label="Benign")))
    assert quality.skipped_header_rows == 0
    assert quality.accepted == 1


def test_blank_rows_are_counted_separately_from_rejections():
    events, quality = _import(_csv(_row(), ",,,,,,,,,,,", _row(sport="40001")))
    assert quality.skipped_blank_rows == 1
    assert quality.rejected == 0
    assert quality.accepted == 2


# ──────────────────────────────────────────────────────────────────
# 9–10. Numeric policy
# ──────────────────────────────────────────────────────────────────


def test_missing_malformed_negative_and_non_finite_are_counted_distinctly():
    q = ImportQuality()
    assert parse_numeric("", "c", q)[0] is None
    assert parse_numeric("abc", "c", q)[0] is None
    assert parse_numeric("-5", "c", q)[0] is None
    assert parse_numeric("Infinity", "c", q)[0] is None
    assert parse_numeric("NaN", "c", q)[0] is None

    assert q.missing_values["c"] == 1
    assert q.malformed_values["c"] == 1
    assert q.invalid_negative_values["c"] == 1
    assert q.non_finite_values["c"] == 2


def test_a_recorded_zero_survives_as_zero():
    """0 bytes is a measurement. Truthiness-based parsing loses it."""
    q = ImportQuality()
    value, reject = parse_numeric("0", "bytes", q)
    assert value == 0.0 and reject is None
    assert "bytes" not in q.missing_values


def test_a_legitimately_negative_column_is_allowed_when_declared():
    q = ImportQuality()
    assert parse_numeric("-5", "offset", q, allow_negative=True)[0] == -5.0
    assert "offset" not in q.invalid_negative_values


def test_non_finite_values_never_reach_an_event():
    import math

    events, quality = _import(_csv(_row(dur="Infinity", fwd_b="NaN")))
    assert quality.accepted == 1
    event = events[0]
    assert event.duration is None
    assert event.bytes_total is None
    for value in (event.duration, event.bytes_total, event.packets):
        assert value is None or math.isfinite(value)


def test_quality_counts_reconcile_with_rows_processed():
    text = _csv(_row(), HEADER, _row(ts="bad"), ",,,,,,,,,,,", _row(sport="40002"))
    _, quality = _import(text)
    assert quality.rows_read == 5
    assert quality.reconciles(), quality.as_dict()


# ──────────────────────────────────────────────────────────────────
# 11. Packet and byte direction semantics
# ──────────────────────────────────────────────────────────────────


def test_forward_and_backward_counts_are_summed_into_totals():
    events, _ = _import(_csv(_row(fwd_p="10", bwd_p="7", fwd_b="1000", bwd_b="500")))
    assert events[0].packets == 17
    assert events[0].bytes_total == 1500


def test_a_forward_only_file_leaves_totals_empty_rather_than_half_filled():
    """
    The schema documents these as totals. Reporting a forward-only count
    under that name misstates the measurement.
    """
    header = "Timestamp,Src IP,Dst IP,Src Port,Dst Port,Protocol,Flow Duration,Tot Fwd Pkts,TotLen Fwd Pkts,Label"
    text = f"{header}\n2018-02-14 10:32:00,192.0.2.10,198.51.100.20,40000,443,6,2500000,10,1000,Benign\n"
    events, _ = import_research_csv(
        csv_text=text, source_id="c", source_sha256="b" * 64, policy=_policy()
    )
    assert events[0].packets is None
    assert events[0].bytes_total is None
    assert QualityFlag.SOURCE_LIMITED in events[0].quality_flags


def test_forward_only_can_be_accepted_when_explicitly_permitted():
    header = "Timestamp,Src IP,Dst IP,Src Port,Dst Port,Protocol,Flow Duration,Tot Fwd Pkts,TotLen Fwd Pkts,Label"
    text = f"{header}\n2018-02-14 10:32:00,192.0.2.10,198.51.100.20,40000,443,6,2500000,10,1000,Benign\n"
    events, _ = import_research_csv(
        csv_text=text, source_id="c", source_sha256="b" * 64,
        policy=_policy(require_bidirectional_counts=False),
    )
    assert events[0].packets == 10


def test_an_empty_backward_cell_is_not_read_as_a_genuine_zero():
    events, _ = _import(_csv(_row(bwd_p="", bwd_b="")))
    assert events[0].packets is None
    assert events[0].bytes_total is None


# ──────────────────────────────────────────────────────────────────
# 12–13. Deterministic identity
# ──────────────────────────────────────────────────────────────────


def test_event_ids_are_deterministic_across_repeated_imports():
    text = _csv(_row(), _row(sport="40001"))
    first, _ = _import(text)
    second, _ = _import(text)
    assert [e.event_id for e in first] == [e.event_id for e in second]


def test_a_different_source_file_yields_different_ids():
    text = _csv(_row())
    a, _ = _import(text, digest="a" * 64)
    b, _ = _import(text, digest="c" * 64)
    assert a[0].event_id != b[0].event_id


def test_byte_identical_rows_are_counted_as_exact_duplicates_and_kept():
    """
    Event identity is (file, row index, content) by design, so two rows in
    one file can never collide on identity — which left
    `duplicate_rows_exact` permanently zero. It now counts rows whose RAW
    TEXT repeats, a documented CICFlowMeter artefact.

    Both rows are still stored: two identical-looking flows may be two real
    events, and dropping one would delete an observation.
    """
    events, quality = _import(_csv(_row(), _row()))

    assert quality.accepted == 2
    assert quality.duplicate_rows_exact == 1, "a byte-identical row was not counted"
    assert events[0].event_id != events[1].event_id
    # The canonical-field counter is a superset: a byte-identical row also
    # matches canonically.
    assert quality.near_duplicate_flows == 1


def test_canonically_equal_rows_differing_only_in_an_unmapped_column():
    """
    Same 5-tuple, time and label; different raw text. Not a byte duplicate,
    but still worth reporting to an operator auditing a corpus.
    """
    header = HEADER + ",Flow Bytes/s"
    base = _row() + ",1000"
    variant = _row() + ",2000"
    text = chr(10).join([header, base, variant]) + chr(10)
    events, quality = import_research_csv(
        csv_text=text, source_id="c", source_sha256="a" * 64, policy=_policy()
    )

    assert quality.accepted == 2
    assert quality.duplicate_rows_exact == 0, "the rows differ in raw text"
    assert quality.near_duplicate_flows == 1


def test_distinct_rows_are_counted_as_neither():
    events, quality = _import(_csv(_row(sport="40000"), _row(sport="40001")))
    assert quality.accepted == 2
    assert quality.duplicate_rows_exact == 0
    assert quality.near_duplicate_flows == 0


def test_identity_material_is_order_independent_for_the_same_row():
    assert deterministic_event_id("a" * 64, 3, "x=1|y=2") == deterministic_event_id(
        "a" * 64, 3, "x=1|y=2"
    )
    assert deterministic_event_id("a" * 64, 3, "x=1") != deterministic_event_id(
        "a" * 64, 4, "x=1"
    )


# ──────────────────────────────────────────────────────────────────
# 14. Source hashing and manifest
# ──────────────────────────────────────────────────────────────────


def test_file_and_byte_hashes_agree(tmp_path):
    path = tmp_path / "f.csv"
    payload = _csv(_row()).encode("utf-8")
    path.write_bytes(payload)
    assert sha256_file(str(path)) == sha256_bytes(payload)


def test_manifest_records_policy_hash_and_quality(tmp_path):
    _, quality = _import(_csv(_row()))
    manifest = build_manifest(
        dataset_name="EXAMPLE-CORPUS",
        dataset_release="v1",
        source_filename=str(tmp_path / "deep" / "path" / "flows.csv"),
        source_sha256="d" * 64,
        source_size_bytes=123,
        source_id="corpus",
        data_category="historical_import",
        policy=_policy().describe(),
        quality=quality,
        unit_conversions=["duration: microseconds -> seconds"],
    )
    assert manifest.source_sha256 == "d" * 64
    assert manifest.policy["duration_unit"] == "microseconds"
    assert manifest.quality["accepted"] == 1
    # An absolute path would leak the operator's home directory.
    assert manifest.source_filename == "flows.csv"
    assert "/" not in manifest.source_filename and "\\" not in manifest.source_filename
    assert any("byte identity" in n for n in manifest.notes)


def test_manifest_round_trips_atomically(tmp_path):
    _, quality = _import(_csv(_row()))
    manifest = build_manifest(
        dataset_name="X", dataset_release=None, source_filename="a.csv",
        source_sha256="e" * 64, source_size_bytes=1, source_id="c",
        data_category="historical_import", policy={}, quality=quality,
    )
    path = save_manifest(manifest, tmp_path / "manifests")
    assert path.exists()
    assert not list((tmp_path / "manifests").glob("*.tmp"))
    assert load_manifest(path).source_sha256 == "e" * 64
    assert json.loads(path.read_text(encoding="utf-8"))["dataset_name"] == "X"


def test_the_same_bytes_map_to_the_same_manifest_file(tmp_path):
    _, quality = _import(_csv(_row()))

    def _m(name):
        return build_manifest(
            dataset_name=name, dataset_release=None, source_filename="a.csv",
            source_sha256="f" * 64, source_size_bytes=1, source_id="c",
            data_category="historical_import", policy={}, quality=quality,
        )

    first = save_manifest(_m("first"), tmp_path / "m")
    second = save_manifest(_m("second"), tmp_path / "m")
    assert first == second
    assert len(list((tmp_path / "m").glob("import-*.json"))) == 1


# ──────────────────────────────────────────────────────────────────
# API: fail-closed behaviour end to end
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def api(tmp_path):
    """A client whose operational DB is a temp file, as conftest guarantees."""
    operational = Database(db_path=str(tmp_path / "operational.db"))
    operational.initialize()
    app.dependency_overrides[get_db] = lambda: operational
    reset_research_db()
    yield operational, tmp_path
    app.dependency_overrides.clear()
    get_config.cache_clear()
    reset_research_db()
    operational.close()


def test_research_import_is_refused_without_a_configured_store(api, monkeypatch):
    operational, tmp_path = api
    monkeypatch.delenv("PRAHARI_RESEARCH_DATABASE_URL", raising=False)
    get_config.cache_clear()

    with TestClient(app) as client:
        res = client.get("/api/v1/research/import/status")
        assert res.status_code == 200
        assert res.json()["configured"] is False
        assert res.json()["fail_closed"] is True

        res = client.post(
            "/api/v1/research/import/csv",
            json={
                "file_path": str(tmp_path / "x.csv"),
                "dataset_name": "X",
                "source_id": "corpus",
            },
        )
        assert res.status_code == 409
        assert res.json()["detail"]["error"] == "research_database_not_configured"


def test_research_import_writes_only_to_the_isolated_store(api, monkeypatch, tmp_path):
    operational, _ = api
    research_path = tmp_path / "research.db"
    monkeypatch.setenv("PRAHARI_RESEARCH_DATABASE_URL", f"sqlite:///{research_path}")
    get_config.cache_clear()
    reset_research_db()

    corpus = tmp_path / "corpus.csv"
    corpus.write_text(_csv(_row(), _row(sport="40001")), encoding="utf-8")

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/research/import/csv",
            json={
                "file_path": str(corpus),
                "dataset_name": "EXAMPLE-CORPUS",
                "source_id": "corpus",
                "timestamp_format": "iso",
                "duration_unit": "microseconds",
                "dry_run": False,
            },
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["events_persisted"] == 2
        assert body["manifest"]["source_sha256"]
        assert Path(body["research_database"]) == research_path.resolve()

    # The operational database saw nothing.
    assert operational.count_events() == 0
    research = Database(db_path=str(research_path))
    assert research.count_events(source_id="corpus") == 2
    research.close()


def test_research_import_dry_run_writes_nothing(api, monkeypatch, tmp_path):
    operational, _ = api
    research_path = tmp_path / "research.db"
    monkeypatch.setenv("PRAHARI_RESEARCH_DATABASE_URL", f"sqlite:///{research_path}")
    get_config.cache_clear()
    reset_research_db()

    corpus = tmp_path / "c.csv"
    corpus.write_text(_csv(_row()), encoding="utf-8")

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/research/import/csv",
            json={
                "file_path": str(corpus), "dataset_name": "X", "source_id": "c",
                "timestamp_format": "iso", "duration_unit": "microseconds",
            },
        )
    body = res.json()
    assert body["dry_run"] is True
    assert body["events_normalized"] == 1
    assert body["events_persisted"] == 0
    assert body["manifest_path"] is None


def test_repeat_import_of_the_same_file_persists_nothing_new(api, monkeypatch, tmp_path):
    operational, _ = api
    research_path = tmp_path / "research.db"
    monkeypatch.setenv("PRAHARI_RESEARCH_DATABASE_URL", f"sqlite:///{research_path}")
    get_config.cache_clear()
    reset_research_db()

    corpus = tmp_path / "c.csv"
    corpus.write_text(_csv(_row(), _row(sport="40001")), encoding="utf-8")
    payload = {
        "file_path": str(corpus), "dataset_name": "X", "source_id": "c",
        "timestamp_format": "iso", "duration_unit": "microseconds",
        "dry_run": False,
    }

    with TestClient(app) as client:
        first = client.post("/api/v1/research/import/csv", json=payload).json()
        second = client.post("/api/v1/research/import/csv", json=payload).json()

    assert first["events_persisted"] == 2
    assert second["events_persisted"] == 0, "re-import duplicated the corpus"


def test_general_csv_endpoint_refuses_research_data_into_operational_storage(
    monkeypatch, tmp_path
):
    """
    The guard that matters in production: the convenience importer must not
    accept a benchmark corpus aimed at the live telemetry database.
    """
    config = get_config()
    operational = Database(db_path=str(config.get_database_path()))

    class _NoWriteDatabase(Database):
        """Proves refusal happens before any write is attempted."""

        def insert_events(self, *a, **k):  # noqa: D102
            raise AssertionError("a write was attempted despite the guard")

    guarded = _NoWriteDatabase(db_path=str(config.get_database_path()))
    app.dependency_overrides[get_db] = lambda: guarded
    try:
        with TestClient(app) as client:
            res = client.post(
                "/api/v1/import/csv/raw",
                json={
                    "source_id": "corpus",
                    "csv_content": _csv(_row()),
                    "data_category": "historical_import",
                },
            )
        assert res.status_code == 409
        assert res.json()["detail"]["error"] == "research_import_into_operational_database"
    finally:
        app.dependency_overrides.clear()
        operational.close()
