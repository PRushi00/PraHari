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

    credential, token = Credential.create(
        source_id=args.source_id, role=role, description=args.description
    )
    records.append(credential.to_record())
    _save(path, records)

    print(f"[OK] Created credential {credential.credential_id}")
    print(f"     source_id : {credential.source_id}")
    print(f"     role      : {credential.role.value}")
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
    print(f"{'CREDENTIAL ID':18} {'SOURCE':24} {'ROLE':10} {'ENABLED':8} DESCRIPTION")
    print("-" * 92)
    for r in records:
        print(
            f"{r.get('credential_id',''):18} {r.get('source_id',''):24} "
            f"{r.get('role',''):10} {str(r.get('enabled', True)):8} "
            f"{r.get('description','')}"
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
    p_add.set_defaults(func=cmd_add)

    p_list = sub.add_parser("list", help="List credentials (never tokens)")
    p_list.add_argument("--file", required=True)
    p_list.set_defaults(func=cmd_list)

    p_dis = sub.add_parser("disable", help="Disable a credential")
    p_dis.add_argument("--file", required=True)
    p_dis.add_argument("--credential-id", required=True)
    p_dis.set_defaults(func=cmd_disable)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
