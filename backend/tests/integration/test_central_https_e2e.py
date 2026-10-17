"""
PraHari — Central Ingestion Over Real HTTPS, Out of Process (ADR-066, ADR-067).

Every earlier central-mode test ran the application in-process through
`TestClient`: no socket, no TLS, no separate interpreter. That proves the
handlers, not the deployment. This module starts PraHari as its own
`uvicorn` process serving HTTPS on a loopback port, and drives it with the
real sensor agent over a real TLS connection.

What is real here
-----------------
* A separate server process, its own interpreter, a real listening socket.
* TLS, with a test PKI minted per run by the OpenSSL CLI: a test CA, a
  server certificate for 127.0.0.1, a certificate for the WRONG host, and
  a certificate from a ROGUE CA the agent was never told to trust.
* Central mode with hashed credentials loaded from a file, exactly as an
  operator would deploy it.

What is NOT claimed
-------------------
* Not a remote deployment. Everything is on 127.0.0.1; no LAN, no public
  network, no production certificate, no TLS terminator. A localhost test
  certificate proves the client and server handle TLS correctly — it says
  nothing about a real deployment's certificate management.
* Not a load test.

Safety
------
The database is a fresh file under pytest's temporary directory, the
credentials are minted per run and never printed, the server binds only to
127.0.0.1 on an ephemeral port, and it is stopped — and the port verified
closed — at the end of the module. Nothing touches either operational
database.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import replace
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from app.agents.sensor_agent import AgentConfig, ConfigError, SensorAgent
from app.core.security import Credential, Role

BACKEND = Path(__file__).resolve().parents[2]
INGEST_PATH = "/api/v1/stream/ingest/ndjson"


def _find_openssl() -> str | None:
    found = shutil.which("openssl")
    if found:
        return found
    for candidate in (
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files\Git\mingw64\bin\openssl.exe",
    ):
        if os.path.isfile(candidate):
            return candidate
    return None


OPENSSL = _find_openssl()

pytestmark = pytest.mark.skipif(
    OPENSSL is None,
    reason="the OpenSSL CLI is needed to mint a throwaway test PKI",
)


# ──────────────────────────────────────────────────────────────────
# Test PKI
# ──────────────────────────────────────────────────────────────────


def _openssl(*args: str, cwd: Path) -> None:
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    result = subprocess.run(
        [OPENSSL, *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args[:2])} failed: {result.stderr[-500:]}")


def _make_ca(d: Path, name: str) -> tuple[Path, Path]:
    key, cert = d / f"{name}.key", d / f"{name}.pem"
    _openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
        "-keyout", str(key), "-out", str(cert), "-subj", f"/CN=PraHari {name} (test only)",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        cwd=d,
    )
    return key, cert


def _make_leaf(d: Path, name: str, ca: tuple[Path, Path], san: str) -> tuple[Path, Path]:
    key, csr, cert = d / f"{name}.key", d / f"{name}.csr", d / f"{name}.pem"
    ext = d / f"{name}.ext"
    ext.write_text(
        f"subjectAltName={san}\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid\n",
        encoding="utf-8",
    )
    _openssl(
        "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
        "-out", str(csr), "-subj", f"/CN={name}", cwd=d,
    )
    _openssl(
        "x509", "-req", "-sha256", "-days", "2", "-in", str(csr),
        "-CA", str(ca[1]), "-CAkey", str(ca[0]), "-CAcreateserial",
        "-extfile", str(ext), "-out", str(cert), cwd=d,
    )
    return key, cert


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    ca = _make_ca(d, "test-ca")
    rogue = _make_ca(d, "rogue-ca")
    return {
        "dir": d,
        "ca_pem": str(ca[1]),
        "server": _make_leaf(d, "server", ca, "IP:127.0.0.1,DNS:localhost"),
        "wrong_host": _make_leaf(d, "wrong-host", ca, "DNS:not-this-host.invalid"),
        "rogue_server": _make_leaf(d, "rogue-server", rogue, "IP:127.0.0.1,DNS:localhost"),
    }


# ──────────────────────────────────────────────────────────────────
# The PraHari server process
# ──────────────────────────────────────────────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _port_is_listening(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _kill_tree(proc: subprocess.Popen) -> None:
    """
    Stop the server and everything it started.

    On Windows a venv's python.exe is a launcher that runs the real
    interpreter as a child, so terminating the launcher alone could leave
    a listener behind. The whole tree is stopped, and the caller verifies
    the port actually closed rather than assuming it.
    """
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            capture_output=True, timeout=30,
        )
    else:
        proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=15)


class Central:
    """A running central-mode PraHari, and the handles a test needs."""

    def __init__(self, port, db_path, creds_path, log_path, tokens, creds, ca_pem, proc):
        self.port = port
        self.db_path = db_path
        self.creds_path = creds_path
        self.log_path = log_path
        self.tokens = tokens
        self.creds = creds
        self.ca_pem = ca_pem
        self.proc = proc

    @property
    def base(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    @property
    def ingest_url(self) -> str:
        return self.base + INGEST_PATH

    def context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=self.ca_pem)

    def request(self, method, path, body=None, token=None, headers=None):
        h = {"Content-Type": "application/json", **(headers or {})}
        if token:
            h["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode() if isinstance(body, (dict, list)) else body
        req = urllib.request.Request(self.base + path, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, context=self.context(), timeout=30) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), exc.read()

    def rows(self, sql, params=()):
        # Read-only URI: the test inspects the server's database without
        # ever becoming a second writer to it.
        conn = sqlite3.connect(f"file:{self.db_path.as_posix()}?mode=ro", uri=True)
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def write_credentials(self) -> None:
        self.creds_path.write_text(
            json.dumps([c.to_record() for c in self.creds.values()]), encoding="utf-8"
        )


def _start_central(tmp: Path, pki: dict, port: int | None = None) -> Central:
    port = port or _free_port()
    db_path = tmp / "central.db"
    creds_path = tmp / "credentials.json"
    log_path = tmp / "server.log"

    creds, tokens = {}, {}
    for name, source, role in (
        ("a", "sensor-a", Role.INGEST),
        ("b", "sensor-b", Role.INGEST),
        ("revoke_me", "sensor-c", Role.INGEST),
        ("rl", "sensor-rl", Role.INGEST),
        ("reader", "sensor-a", Role.READ_ONLY),
        ("admin", "ops", Role.ADMIN),
    ):
        cred, token = Credential.create(source_id=source, role=role, description=f"test {name}")
        creds[name], tokens[name] = cred, token

    central = Central(port, db_path, creds_path, log_path, tokens, creds, pki["ca_pem"], None)
    central.write_credentials()

    env = {k: v for k, v in os.environ.items() if not k.startswith("PRAHARI_")}
    env.update({
        "PRAHARI_DEPLOYMENT_MODE": "central",
        "PRAHARI_DATABASE_URL": f"sqlite:///{db_path.as_posix()}",
        "PRAHARI_CREDENTIALS_FILE": str(creds_path),
        "PRAHARI_MAX_REQUEST_SIZE_MB": "1",
        "PRAHARI_RATE_LIMIT_REQUESTS": "40",
        "PRAHARI_RATE_LIMIT_WINDOW_SECONDS": "60",
    })
    key, cert = pki["server"]
    log = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", "app.main:app",
            "--app-dir", str(BACKEND),
            "--host", "127.0.0.1", "--port", str(port),
            "--ssl-keyfile", str(key), "--ssl-certfile", str(cert),
            "--log-level", "info",
        ],
        cwd=str(tmp),  # never the repository: no stray .env, no stray files
        env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    central.proc = proc

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            log.flush()
            raise RuntimeError("central server exited during startup:\n" + log_path.read_text()[-3000:])
        try:
            status, _, _ = central.request("GET", "/api/v1/health")
            if status == 200:
                return central
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.25)
    _kill_tree(proc)
    raise RuntimeError("central server did not become healthy:\n" + log_path.read_text()[-3000:])


@pytest.fixture(scope="module")
def central(tmp_path_factory, pki):
    tmp = tmp_path_factory.mktemp("central")
    server = _start_central(tmp, pki)
    yield server
    _kill_tree(server.proc)
    assert not _port_is_listening(server.port), "the server's port is still open after shutdown"


def _event(i: int, prefix: str) -> dict:
    return {
        "event_id": f"{prefix}-{i}",
        "timestamp": "2026-06-01T12:00:00Z",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "src_port": 40000 + i,
        "dst_port": 443,
        "proto": "tcp",
    }


def _agent(central: Central, who: str = "a", source: str = "sensor-a", **overrides) -> SensorAgent:
    cfg = AgentConfig(
        endpoint=central.ingest_url,
        source_id=source,
        token=central.tokens[who],
        batch_size=50,
        max_attempts=2,
        base_backoff_seconds=0.01,
        max_backoff_seconds=0.02,
        ca_file=central.ca_pem,
        **overrides,
    )
    return SensorAgent(cfg, sleep_fn=lambda s: None)


def _count_source(central: Central, source: str) -> int:
    return central.rows(
        "SELECT COUNT(*) FROM normalized_events WHERE source_id = ?", (source,)
    )[0][0]


# ──────────────────────────────────────────────────────────────────
# The listener itself
# ──────────────────────────────────────────────────────────────────


def test_the_server_is_a_separate_process_listening_on_loopback_only(central):
    assert central.proc.poll() is None
    assert central.proc.pid != os.getpid()
    assert _port_is_listening(central.port)
    # Loopback only: the address it was told to bind is the only one used.
    assert "127.0.0.1" in central.base


def test_health_over_verified_tls_carries_a_request_id(central):
    status, headers, body = central.request("GET", "/api/v1/health")

    assert status == 200
    lowered = {k.lower(): v for k, v in headers.items()}
    assert lowered.get("x-request-id"), "the correlation id must survive a real TLS hop"
    assert json.loads(body)["deployment_mode"] == "central"


def test_plaintext_to_the_tls_port_is_not_served(central):
    """There is no plaintext fallback on the TLS listener."""
    import http.client

    req = urllib.request.Request(f"http://127.0.0.1:{central.port}/api/v1/health")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            status = r.status
    except urllib.error.HTTPError as exc:
        status = exc.code  # answered with an error: still not served
    except (urllib.error.URLError, ConnectionError, OSError, http.client.HTTPException):
        status = None  # the connection was refused or dropped
    assert status != 200, "the TLS listener served a plaintext request"


# ──────────────────────────────────────────────────────────────────
# The agent over verified TLS
# ──────────────────────────────────────────────────────────────────


def test_agent_delivers_over_verified_tls_and_the_rows_land(central):
    agent = _agent(central)
    agent.offer_many([_event(i, "tls-ok") for i in range(5)])

    result = agent.flush_once()

    assert result.ok, (result.error_kind, result.detail)
    assert result.stored == 5
    assert agent.buffered == 0
    ids = {r[0] for r in central.rows("SELECT event_id FROM normalized_events WHERE source_id='sensor-a'")}
    assert len(ids) >= 5


def test_redelivery_of_the_same_batch_is_deduplicated_not_duplicated(central):
    before = _count_source(central, "sensor-a")
    events = [_event(i, "tls-dup") for i in range(4)]

    first = _agent(central)
    first.offer_many(events)
    r1 = first.flush_once()

    second = _agent(central)
    second.offer_many(events)  # the at-least-once retry a lost ACK causes
    r2 = second.flush_once()

    assert r1.ok and r1.stored == 4
    assert r2.ok and r2.stored == 0 and r2.duplicates == 4
    assert _count_source(central, "sensor-a") == before + 4


def test_ingest_is_audited_with_the_real_actor_and_the_request_id(central):
    """
    ADR-067: before this, the entry said "local_operator" — a person at
    the console who did nothing. It must name the credential that acted.
    """
    agent = _agent(central)
    agent.offer_many([_event(i, "tls-audit") for i in range(2)])
    assert agent.flush_once().ok

    rows = central.rows(
        "SELECT user_identity, request_id FROM audit_events "
        "WHERE action='ingest_ndjson_stream' ORDER BY id DESC LIMIT 1"
    )
    identity, request_id = rows[0]
    cred = central.creds["a"]
    assert identity == f"credential:{cred.credential_id} source:sensor-a role:ingest"
    assert identity != "local_operator"
    assert request_id, "a request id must be recorded across a real network hop"


def test_a_supplied_request_id_is_the_one_audited(central):
    body = {
        "source_id": "sensor-b",
        "ndjson_content": json.dumps(_event(1, "tls-rid")) + "\n",
        "data_category": "live_telemetry",
    }
    status, headers, _ = central.request(
        "POST", INGEST_PATH, body, token=central.tokens["b"],
        headers={"X-Request-ID": "sensor-b-batch-0001"},
    )

    assert status == 200
    rows = central.rows(
        "SELECT user_identity FROM audit_events WHERE request_id = ?", ("sensor-b-batch-0001",)
    )
    assert len(rows) == 1
    assert "source:sensor-b" in rows[0][0]


# ──────────────────────────────────────────────────────────────────
# Certificate validation: every failure keeps the events
# ──────────────────────────────────────────────────────────────────


def test_without_the_ca_the_agent_refuses_and_keeps_every_event(central):
    before = _count_source(central, "sensor-a")
    cfg = AgentConfig(
        endpoint=central.ingest_url, source_id="sensor-a",
        token=central.tokens["a"], batch_size=50, max_attempts=3,
    )  # no ca_file: the system store does not trust the test CA
    agent = SensorAgent(cfg, sleep_fn=lambda s: None)
    agent.offer_many([_event(i, "tls-untrusted") for i in range(3)])

    result = agent.flush_once()

    assert not result.ok
    assert result.error_kind == "tls_verification_failed"
    assert result.halt and not result.retryable
    assert agent.buffered == 3, "an untrusted channel must not cost the events"
    assert agent.stats.retries == 0, "a certificate failure is not transient"
    assert agent.stats.batches_failed_permanent == 0, "the events were not at fault"
    assert agent.health()["channel_refusals"] == 1
    assert _count_source(central, "sensor-a") == before


def test_flush_all_does_not_spin_on_a_refused_channel(central):
    cfg = AgentConfig(
        endpoint=central.ingest_url, source_id="sensor-a",
        token=central.tokens["a"], batch_size=1,
    )
    agent = SensorAgent(cfg, sleep_fn=lambda s: None)
    agent.offer_many([_event(i, "tls-spin") for i in range(20)])

    agent.flush_all(max_batches=100)

    assert agent.stats.batches_sent == 1, "it must stop at the first refusal, not retry 20 batches"
    assert agent.buffered == 20


class _Recorder(BaseHTTPRequestHandler):
    def _handle(self):
        self.server.hits.append({"method": self.command, "path": self.path,
                                 "headers": {k.lower(): v for k, v in self.headers.items()}})
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if self.server.redirect_to:
            self.send_response(302)
            self.send_header("Location", self.server.redirect_to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b'{"stored_records": 0, "duplicate_records": 0}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = _handle
    do_GET = _handle

    def log_message(self, *args):  # keep test output clean
        pass


@pytest.fixture
def serve():
    started = []

    def _start(cert_key=None, redirect_to=None):
        srv = HTTPServer(("127.0.0.1", 0), _Recorder)
        srv.hits, srv.redirect_to = [], redirect_to
        if cert_key:
            key, cert = cert_key
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(cert), str(key))
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        started.append(srv)
        scheme = "https" if cert_key else "http"
        return srv, f"{scheme}://127.0.0.1:{srv.server_address[1]}"

    yield _start
    for srv in started:
        srv.shutdown()
        srv.server_close()


def _agent_to(url: str, ca_pem: str, token="test-token-not-a-secret") -> SensorAgent:
    cfg = AgentConfig(endpoint=url + INGEST_PATH, source_id="s", token=token,
                      batch_size=10, max_attempts=3, ca_file=ca_pem)
    return SensorAgent(cfg, sleep_fn=lambda s: None)


def test_hostname_mismatch_is_rejected_even_from_the_trusted_ca(pki, serve):
    srv, url = serve(cert_key=pki["wrong_host"])
    agent = _agent_to(url, pki["ca_pem"])
    agent.offer(_event(1, "mismatch"))

    result = agent.flush_once()

    assert result.error_kind == "tls_verification_failed"
    assert "hostname" in result.detail.lower() or "ip address" in result.detail.lower()
    assert srv.hits == [], "no HTTP request may be sent over an unverified channel"
    assert agent.buffered == 1


def test_a_certificate_from_an_untrusted_issuer_is_rejected(pki, serve):
    srv, url = serve(cert_key=pki["rogue_server"])
    agent = _agent_to(url, pki["ca_pem"])
    agent.offer(_event(1, "rogue"))

    result = agent.flush_once()

    assert result.error_kind == "tls_verification_failed"
    assert srv.hits == []
    assert agent.buffered == 1


def test_verification_cannot_be_switched_off():
    with pytest.raises(ConfigError, match="cannot be disabled"):
        AgentConfig(endpoint="https://central.invalid/x", source_id="s",
                    token="t", verify_tls=False)


def test_a_missing_ca_file_is_refused_at_configuration_time(tmp_path):
    with pytest.raises(ConfigError, match="ca_file"):
        AgentConfig(endpoint="https://central.invalid/x", source_id="s",
                    token="t", ca_file=str(tmp_path / "absent.pem"))


# ──────────────────────────────────────────────────────────────────
# Redirects: the plaintext-credential hazard
# ──────────────────────────────────────────────────────────────────


def test_the_redirect_hazard_is_real_for_a_default_urllib_client(pki, serve):
    """
    Evidence for the fix, not a test of PraHari: CPython's default opener
    follows an HTTPS 302 to plain HTTP and carries Authorization with it.
    This is the behaviour the agent used before ADR-066.
    """
    plain, plain_url = serve()
    _, tls_url = serve(cert_key=pki["server"], redirect_to=plain_url + "/captured")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=pki["ca_pem"]))
    )
    req = urllib.request.Request(tls_url + INGEST_PATH, data=b"{}", method="POST",
                                 headers={"Authorization": "Bearer would-leak"})
    with opener.open(req, timeout=10):
        pass

    assert plain.hits, "the default client followed the redirect"
    assert plain.hits[0]["headers"].get("authorization") == "Bearer would-leak", (
        "the bearer token crossed to plaintext - this is the hazard"
    )


def test_the_agent_never_follows_a_redirect_to_plaintext(pki, serve):
    plain, plain_url = serve()
    tls, tls_url = serve(cert_key=pki["server"], redirect_to=plain_url + "/captured")
    agent = _agent_to(tls_url, pki["ca_pem"], token="must-not-leak-token")
    agent.offer(_event(1, "redirect"))

    result = agent.flush_once()

    assert len(tls.hits) == 1
    assert plain.hits == [], "the agent followed a redirect off the verified channel"
    assert result.error_kind == "redirect_refused"
    assert result.halt and not result.retryable
    assert agent.buffered == 1


# ──────────────────────────────────────────────────────────────────
# Authentication, authorization and limits, over the wire
# ──────────────────────────────────────────────────────────────────


def _ndjson_body(source: str, prefix: str, n: int = 1) -> dict:
    return {
        "source_id": source,
        "ndjson_content": "".join(json.dumps(_event(i, prefix)) + "\n" for i in range(n)),
        "data_category": "live_telemetry",
    }


def test_no_credential_is_401(central):
    status, headers, _ = central.request("POST", INGEST_PATH, _ndjson_body("sensor-a", "noauth"))
    assert status == 401
    assert {k.lower(): v for k, v in headers.items()}.get("www-authenticate") == "Bearer"


def test_an_invalid_credential_is_401_and_dropped_not_retried(central):
    agent = _agent(central)
    agent.config = replace(agent.config, token="not-a-real-token-at-all")
    agent.offer(_event(1, "badtoken"))

    result = agent.flush_once()

    assert result.status == 401
    assert not result.retryable and not result.halt
    assert agent.stats.retries == 0


def test_a_credential_cannot_write_another_sources_telemetry(central):
    before = _count_source(central, "sensor-b")
    status, _, body = central.request(
        "POST", INGEST_PATH, _ndjson_body("sensor-b", "crosssource"), token=central.tokens["a"]
    )
    assert status == 403, body
    assert _count_source(central, "sensor-b") == before


def test_a_read_only_credential_cannot_ingest(central):
    status, _, _ = central.request(
        "POST", INGEST_PATH, _ndjson_body("sensor-a", "readonly"), token=central.tokens["reader"]
    )
    assert status == 403


def test_a_revoked_credential_stops_working_without_a_restart(central):
    ok, _, _ = central.request(
        "POST", INGEST_PATH, _ndjson_body("sensor-c", "pre-revoke"), token=central.tokens["revoke_me"]
    )
    assert ok == 200

    central.creds["revoke_me"] = replace(
        central.creds["revoke_me"],
        revoked_at=datetime.now(timezone.utc).isoformat(),
        revoked_reason="test revocation",
    )
    central.write_credentials()

    deadline = time.monotonic() + 10
    status = None
    while time.monotonic() < deadline:
        status, _, _ = central.request(
            "POST", INGEST_PATH, _ndjson_body("sensor-c", "post-revoke"),
            token=central.tokens["revoke_me"],
        )
        if status == 401:
            break
        time.sleep(0.2)
    assert status == 401, "a revoked credential was still accepted"
    assert central.proc.poll() is None, "revocation must not require a restart"


def test_an_oversized_payload_is_refused_before_it_is_stored(central):
    """
    Over a real socket the server refuses on the declared Content-Length
    and closes the connection without reading the body. A client still
    uploading may therefore see the connection drop instead of the 413 -
    which TestClient, having no socket, can never show. Both outcomes are
    accepted from the client's side; the server log must show the 413.
    """
    before = _count_source(central, "sensor-a")
    padding = "x" * (1024 * 1024 + 4096)  # just over the configured 1 MB
    body = {"source_id": "sensor-a", "ndjson_content": padding, "data_category": "live_telemetry"}

    import http.client

    try:
        status, _, _ = central.request("POST", INGEST_PATH, body, token=central.tokens["a"])
    except (urllib.error.URLError, ConnectionError, OSError, http.client.HTTPException):
        # Timing decides which of three shapes the client sees: a clean 413,
        # a dropped connection, or the 413's headers with its body cut off
        # (IncompleteRead). All are the same server behaviour.
        status = None

    assert status in (413, None)
    log = central.log_path.read_text(encoding="utf-8", errors="replace")
    assert "Rejected oversized request" in log and " 413 " in log
    assert _count_source(central, "sensor-a") == before
    assert central.proc.poll() is None


def _big_event(i: int, prefix: str, pad: int) -> dict:
    return {**_event(i, prefix), "note": "x" * pad}


def test_the_agent_splits_a_batch_that_the_server_would_refuse(central):
    """
    The wedge this prevents: 50 events at ~30 KB is ~1.5 MB, over the
    server's 1 MB. Unbounded, the agent sent it, saw the connection drop,
    classified that as transient, and resent the same bytes forever.
    """
    before = _count_source(central, "sensor-a")
    agent = _agent(central, max_request_bytes=900_000)
    agent.offer_many([_big_event(i, "split", 30_000) for i in range(50)])

    agent.flush_all(max_batches=50)

    assert agent.buffered == 0, agent.health()
    assert agent.stats.batches_split >= 1
    assert agent.stats.events_oversized == 0
    assert _count_source(central, "sensor-a") == before + 50


def test_a_single_event_too_large_to_ever_send_is_dropped_not_wedged(central):
    before = _count_source(central, "sensor-a")
    agent = _agent(central, max_request_bytes=200_000)
    agent.offer(_big_event(0, "huge", 400_000))
    agent.offer_many([_event(i, "behind-huge") for i in range(3)])

    agent.flush_all(max_batches=10)

    assert agent.stats.events_oversized == 1
    assert agent.buffered == 0, "the events behind the oversized one must still go"
    assert _count_source(central, "sensor-a") == before + 3


def test_an_agent_bound_above_the_server_limit_never_loses_or_resends_that_batch(central):
    """
    The ADR-066 failure mode, against the real server: the agent's request
    bound is above the server's 1 MB limit, so a 1.5 MB batch goes out.

    Formerly `test_an_unbounded_agent_would_wedge_on_that_batch`, which
    asserted the client always sees a dropped connection. Which shape it
    sees is timing (see the oversized-payload test above): on Windows it was
    the dropped connection, on Linux loopback the 413 usually arrives whole.
    Each shape now has a defined, safe outcome:

    * dropped connection - indistinguishable from an outage, so retryable
      and the events are kept. A round made entirely of such drops splits
      the batch, unconfirmed (ADR-073), so the same bytes are not resent
      forever; a correct `max_request_bytes` still avoids the waste.
    * clean 413 - the server asked for smaller batches. The events are
      kept (never dropped as if invalid), the same bytes are never resent,
      and draining delivers every one in smaller batches.
    """
    before = _count_source(central, "sensor-a")
    agent = _agent(central, max_request_bytes=8 * 1024 * 1024)
    agent.offer_many([_big_event(i, "wedge", 30_000) for i in range(50)])

    result = agent.flush_once()

    assert not result.ok
    assert agent.buffered == 50, "valid events must not be lost to a size refusal"
    assert agent.stats.batches_failed_permanent == 0, "the events were not at fault"
    assert agent.stats.events_oversized == 0
    if result.status == 413:
        assert not result.retryable, "a size refusal must not be resent unchanged"
        assert result.error_kind == "payload_too_large"
        assert agent.stats.batches_split == 1

        agent.flush_all(max_batches=50)

        assert agent.buffered == 0, agent.health()
        assert agent.stats.events_oversized == 0
        assert _count_source(central, "sensor-a") == before + 50
    else:
        assert result.retryable, "a dropped connection looks transient"
        assert result.error_kind == "connection_dropped"
        assert agent.stats.batches_split_unconfirmed == 1

        for _ in range(10):
            agent.flush_all(max_batches=50)
            if agent.buffered == 0:
                break

        assert agent.buffered == 0, agent.health()
        assert _count_source(central, "sensor-a") == before + 50


def test_malformed_records_are_rejected_and_counted_not_stored(central):
    before = _count_source(central, "sensor-b")
    body = {
        "source_id": "sensor-b",
        "ndjson_content": "{not json}\n" + json.dumps({"no": "fields"}) + "\n",
        "data_category": "live_telemetry",
    }
    status, _, raw = central.request("POST", INGEST_PATH, body, token=central.tokens["b"])

    assert status in (200, 400, 422), raw
    if status == 200:
        summary = json.loads(raw)
        assert summary["stored_records"] == 0
        assert summary["rejected_records"] >= 1
    assert _count_source(central, "sensor-b") == before


def test_rate_limiting_applies_per_credential_over_the_wire(central):
    statuses, retry_after = [], None
    for i in range(45):
        status, headers, _ = central.request(
            "POST", INGEST_PATH, _ndjson_body("sensor-rl", f"rl-{i}"), token=central.tokens["rl"]
        )
        statuses.append(status)
        if status == 429 and retry_after is None:
            retry_after = {k.lower(): v for k, v in headers.items()}.get("retry-after")

    assert statuses.count(200) == 40
    assert statuses.count(429) == 5
    assert retry_after is not None and float(retry_after) > 0

    # And another credential is unaffected by sensor-rl's exhaustion.
    status, _, _ = central.request(
        "POST", INGEST_PATH, _ndjson_body("sensor-b", "rl-neighbour"), token=central.tokens["b"]
    )
    assert status == 200


def test_no_token_appears_in_the_server_log(central):
    log = central.log_path.read_text(encoding="utf-8", errors="replace")
    assert log, "the server log should not be empty"
    for name, token in central.tokens.items():
        assert token not in log, f"the {name!r} token was written to the server log"


# ──────────────────────────────────────────────────────────────────
# Reconnect: nothing is lost while the server is down
# ──────────────────────────────────────────────────────────────────


def test_events_survive_a_server_outage_and_deliver_on_reconnect(tmp_path, pki):
    port = _free_port()
    endpoint = f"https://127.0.0.1:{port}{INGEST_PATH}"
    cred, token = Credential.create(source_id="sensor-a", role=Role.INGEST)

    cfg = AgentConfig(endpoint=endpoint, source_id="sensor-a", token=token, batch_size=10,
                      max_attempts=2, base_backoff_seconds=0.01, max_backoff_seconds=0.02,
                      ca_file=pki["ca_pem"])
    agent = SensorAgent(cfg, sleep_fn=lambda s: None)
    agent.offer_many([_event(i, "reconnect") for i in range(3)])

    down = agent.flush_once()
    assert not down.ok and down.retryable and down.error_kind == "connection_error"
    assert agent.buffered == 3, "an outage must not lose events"

    server = _start_central(tmp_path, pki, port=port)
    try:
        # The new server minted its own credentials; give the agent one.
        agent.config = replace(agent.config, token=server.tokens["a"])
        up = agent.flush_once()
        assert up.ok and up.stored == 3
        assert agent.buffered == 0
    finally:
        _kill_tree(server.proc)
    assert not _port_is_listening(port)
