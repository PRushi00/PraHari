#!/usr/bin/env python3
"""
PraHari — Central-Mode Credential Management

Mints and manages credentials for CENTRAL deployment. Local (loopback)
deployment needs none.

The credential file stores **hashes only**. A plaintext token is displayed
exactly once, when it is minted, and cannot be recovered afterwards — if it
is lost, revoke it and mint another.

Usage:
    python scripts/manage_credentials.py init   --file secrets/credentials.json
    python scripts/manage_credentials.py add    --file secrets/credentials.json \\
        --source-id sensor-01 --role ingest
    python scripts/manage_credentials.py list   --file secrets/credentials.json
    python scripts/manage_credentials.py disable --file secrets/credentials.json \\
        --credential-id <id>

Then start PraHari centrally:
    set PRAHARI_DEPLOYMENT_MODE=central
    set PRAHARI_CREDENTIALS_FILE=secrets/credentials.json
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.security import Credential, Role  # noqa: E402


def _load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[ERROR] {path} is not valid JSON: {exc}", file=sys.stderr)
        sys.exit(2)
    if not isinstance(data, list):
        print(f"[ERROR] {path} must contain a JSON array.", file=sys.stderr)
        sys.exit(2)
    return data


def _save(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(records, indent=2, sort_keys=True), encoding="utf-8")
    # Best-effort owner-only permissions. On Windows this is advisory; the
    # real control is keeping the file out of version control.
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def cmd_init(args) -> int:
    path = Path(args.file)
    if path.exists() and not args.force:
        print(f"[ERROR] {path} already exists. Use --force to overwrite.", file=sys.stderr)
        return 2
    _save(path, [])
    print(f"[OK] Initialised empty credential store at {path}")
    print("[INFO] Add this path to .gitignore. It must never be committed.")
    return 0


def cmd_add(args) -> int:
    path = Path(args.file)
    records = _load(path)

    try:
        role = Role(args.role)
    except ValueError:
        print(
            f"[ERROR] Unknown role {args.role!r}. "
            f"Valid: {', '.join(r.value for r in Role)}",
            file=sys.stderr,
        )
        return 2

    not_after = _deadline(getattr(args, "expires_in_days", None))
    credential, token = Credential.create(
        source_id=args.source_id,
        role=role,
        description=args.description,
        not_after=not_after,
    )
    records.append(credential.to_record())
    _save(path, records)

    print(f"[OK] Created credential {credential.credential_id}")
    print(f"     source_id : {credential.source_id}")
    print(f"     role      : {credential.role.value}")
    print(f"     expires   : {credential.not_after or 'never'}")
    print()
    print("     TOKEN (shown once — store it now; it cannot be recovered):")
    print(f"     {token}")
    print()
    print("[INFO] Send it as:  Authorization: Bearer <token>")
    if role is Role.ADMIN:
        print("[WARN] Admin credentials can read ALL sources and the audit log.")
    return 0


def cmd_list(args) -> int:
    records = _load(Path(args.file))
    if not records:
        print("[INFO] No credentials defined.")
        return 0
    print(
        f"{'CREDENTIAL ID':18} {'SOURCE':22} {'ROLE':10} {'STATE':10} "
        f"{'EXPIRES':26} DESCRIPTION"
    )
    print("-" * 110)
    for r in records:
        print(
            f"{r.get('credential_id',''):18} {r.get('source_id',''):22} "
            f"{r.get('role',''):10} {_state(r):10} "
            f"{(r.get('not_after') or 'never'):26} {r.get('description','')}"
        )
    print()
    print("[INFO] Tokens are not stored and cannot be displayed.")
    return 0


def cmd_disable(args) -> int:
    path = Path(args.file)
    records = _load(path)
    found = False
    for r in records:
        if r.get("credential_id") == args.credential_id:
            r["enabled"] = False
            found = True
    if not found:
        print(f"[ERROR] No credential {args.credential_id!r}.", file=sys.stderr)
        return 2
    _save(path, records)
    print(f"[OK] Disabled {args.credential_id}. It will no longer authenticate.")
    return 0



def _deadline(days):
    """An ISO-8601 UTC deadline `days` from now, or None for no expiry."""
    if days is None:
        return None
    if days <= 0:
        raise ValueError("--expires-in-days must be positive")
    return (datetime.now(timezone.utc) + timedelta(days=float(days))).isoformat()


def _state(record: dict) -> str:
    """One word for a credential's lifecycle state."""
    if record.get("revoked_at"):
        return "revoked"
    if not record.get("enabled", True):
        return "disabled"
    not_after = record.get("not_after")
    if not_after:
        try:
            deadline = datetime.fromisoformat(str(not_after))
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) >= deadline:
                return "expired"
        except ValueError:
            return "bad-date"
    return "active"


def cmd_revoke(args) -> int:
    """
    Withdraw a credential permanently.

    Distinct from `disable`, which is a pause an operator may undo.
    Revocation records when and why, and is not reversed by this tool: a
    withdrawn credential is replaced, not resurrected.
    """
    path = Path(args.file)
    records = _load(path)
    target = None
    for r in records:
        if r.get("credential_id") == args.credential_id:
            target = r
    if target is None:
        print(f"[ERROR] No credential {args.credential_id!r}.", file=sys.stderr)
        return 2
    if target.get("revoked_at"):
        print(f"[OK] {args.credential_id} was already revoked at {target['revoked_at']}.")
        return 0

    target["revoked_at"] = datetime.now(timezone.utc).isoformat()
    target["revoked_reason"] = args.reason
    target["enabled"] = False
    _save(path, records)

    print(f"[OK] Revoked {args.credential_id} (source {target.get('source_id','?')}).")
    print(f"     reason: {args.reason or '(none given)'}")
    print("[INFO] A running backend picks this up on its next authenticated")
    print("       request; no restart is required.")
    return 0


def cmd_rotate(args) -> int:
    """
    Issue a replacement credential for the same source.

    The source_id is carried over deliberately: it is the identity that
    scopes ingestion and the idempotency namespace (ADR-050, ADR-051), so
    rotating a secret must not move a sensor's data into a new namespace.

    The old credential keeps working until the overlap expires, so a
    sensor can be reconfigured without a gap. --overlap-days 0 revokes it
    immediately.
    """
    path = Path(args.file)
    records = _load(path)
    old_record = None
    for r in records:
        if r.get("credential_id") == args.credential_id:
            old_record = r
    if old_record is None:
        print(f"[ERROR] No credential {args.credential_id!r}.", file=sys.stderr)
        return 2
    if old_record.get("revoked_at"):
        print(
            f"[ERROR] {args.credential_id} is revoked; rotating it would revive "
            "that identity. Add a new credential instead.",
            file=sys.stderr,
        )
        return 2

    try:
        role = Role(old_record.get("role", "ingest"))
    except ValueError:
        print(
            f"[ERROR] Stored role {old_record.get('role')!r} is not valid.",
            file=sys.stderr,
        )
        return 2

    replacement, token = Credential.create(
        source_id=old_record["source_id"],
        role=role,
        description=old_record.get("description", ""),
        not_after=_deadline(getattr(args, "expires_in_days", None)),
        replaces_credential_id=args.credential_id,
    )
    records.append(replacement.to_record())

    if args.overlap_days <= 0:
        old_record["revoked_at"] = datetime.now(timezone.utc).isoformat()
        old_record["revoked_reason"] = f"rotated to {replacement.credential_id}"
        old_record["enabled"] = False
        overlap_note = "The previous credential is revoked immediately."
    else:
        old_record["not_after"] = _deadline(args.overlap_days)
        overlap_note = (
            f"The previous credential stops working at {old_record['not_after']}."
        )

    _save(path, records)

    print(f"[OK] Rotated {args.credential_id} -> {replacement.credential_id}")
    print(f"     source_id : {replacement.source_id}   (unchanged, by design)")
    print(f"     role      : {replacement.role.value}")
    print(f"     expires   : {replacement.not_after or 'never'}")
    print()
    print("     TOKEN (shown once; it cannot be recovered):")
    print(f"     {token}")
    print()
    print(f"[INFO] {overlap_note}")
    print("[INFO] Reconfigure the sensor, confirm it is reporting, then run")
    print(f"       revoke --credential-id {args.credential_id} to close the overlap early.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)

    common = {"--file": {"required": True, "help": "Credential file path"}}

    p_init = sub.add_parser("init", help="Create an empty credential store")
    p_init.add_argument("--file", required=True)
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_init)

    p_add = sub.add_parser("add", help="Mint a credential for one source")
    p_add.add_argument("--file", required=True)
    p_add.add_argument("--source-id", required=True)
    p_add.add_argument("--role", default="ingest",
                       choices=[r.value for r in Role])
    p_add.add_argument("--description", default="")
    p_add.add_argument(
        "--expires-in-days", type=float, default=None,
        help="Optional lifetime in days. Omitted means it does not expire.",
    )
    p_add.set_defaults(func=cmd_add)

    p_list = sub.add_parser("list", help="List credentials (never tokens)")
    p_list.add_argument("--file", required=True)
    p_list.set_defaults(func=cmd_list)

    p_dis = sub.add_parser("disable", help="Disable a credential")
    p_dis.add_argument("--file", required=True)
    p_dis.add_argument("--credential-id", required=True)

    p_rev = sub.add_parser("revoke", help="Permanently withdraw a credential")
    p_rev.add_argument("--file", required=True)
    p_rev.add_argument("--credential-id", required=True)
    p_rev.add_argument("--reason", default="")

    p_rot = sub.add_parser("rotate", help="Issue a replacement credential")
    p_rot.add_argument("--file", required=True)
    p_rot.add_argument("--credential-id", required=True)
    p_rot.add_argument(
        "--overlap-days", type=float, default=7.0,
        help="How long the OLD credential keeps working. 0 revokes it at once.",
    )
    p_rot.add_argument("--expires-in-days", type=float, default=None)

    p_dis.set_defaults(func=cmd_disable)
    p_rev.set_defaults(func=cmd_revoke)
    p_rot.set_defaults(func=cmd_rotate)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
