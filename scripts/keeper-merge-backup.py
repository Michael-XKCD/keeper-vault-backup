#!/usr/bin/env python3
"""Merge a supplementary Keeper backup into a full one, producing a single file.

A run can leave some records as stubs - a `listing` entry with no `detail` and no
`history` - if Commander failed on them. Re-fetch just those with
`keeper-full-backup.py --only-uids`, then fold the result back in here so there
is one artifact instead of two.

A record in the supplement wins over the same uid in the base, and any error
entry for a uid the supplement fixed is dropped. Nothing else is touched, and a
record only present in the base is left alone.

Both inputs are decrypted in memory with the same passphrase that encrypted
them (from 1Password, or a prompt - see USE_OP), and the result is re-encrypted the same way. Plaintext is never written to
disk. The base file is not modified - the merge goes to a new path.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

# Same switch as keeper-full-backup.py: True reads the passphrase with the
# 1Password CLI (`op`), False asks for it at a prompt.
USE_OP = True

OP_ITEM = os.environ.get("OP_ITEM", "")
OP_FIELD = os.environ.get("OP_FIELD", "password")


def log(msg: str) -> None:
    print(f"[merge] {msg}", file=sys.stderr, flush=True)


def die(msg: str, code: int = 1):
    print(f"[merge] ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def passphrase() -> str:
    if not USE_OP:
        key = getpass.getpass("Backup passphrase: ")
        if not key:
            die("the passphrase is empty", 3)
        return key
    p = subprocess.run(["op", "item", "get", OP_ITEM, "--fields", f"label={OP_FIELD}",
                        "--reveal"], capture_output=True, text=True, timeout=90)
    key = p.stdout.strip()
    if p.returncode != 0 or not key:
        die("could not read the key from 1Password - unlock it and try again", 3)
    return key


def with_passphrase(args: list[str], key: str, data: bytes | None = None):
    """Run gpg with the passphrase on a pipe, never in argv."""
    r, w = os.pipe()
    os.set_inheritable(r, True)
    try:
        with os.fdopen(w, "w") as f:
            f.write(key)
        return subprocess.run(
            ["gpg", "--batch", "--quiet", "--pinentry-mode", "loopback",
             "--passphrase-fd", str(r)] + args,
            input=data, capture_output=True, pass_fds=(r,),
        )
    finally:
        try:
            os.close(r)
        except OSError:
            pass


def load(path: str, key: str) -> dict:
    if not os.path.exists(path):
        die(f"{path} does not exist")
    p = with_passphrase(["--decrypt", path], key)
    if p.returncode != 0:
        die(f"could not decrypt {path}: {p.stderr.decode(errors='replace')[:200]}", 5)
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError as e:
        die(f"{path} decrypted but is not valid JSON: {e}", 5)


def complete(rec: dict) -> bool:
    return "detail" in rec


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("base", help="the full backup .json.gpg")
    ap.add_argument("supplement", help="the supplementary backup .json.gpg")
    ap.add_argument("-o", "--output", required=True, help="merged output .json.gpg")
    ap.add_argument("--op-item", help="1Password item holding the passphrase (or set OP_ITEM)")
    ap.add_argument("--op-field", help="field on that item (default: password, or OP_FIELD)")
    args = ap.parse_args()

    if not args.output.endswith(".gpg"):
        die("output must end in .gpg - the merged file is always encrypted")
    if os.path.exists(args.output):
        die(f"{args.output} already exists - refusing to overwrite")

    global OP_ITEM, OP_FIELD
    if args.op_item:
        OP_ITEM = args.op_item
    if args.op_field:
        OP_FIELD = args.op_field
    if USE_OP and not OP_ITEM:
        die("no 1Password item given. Pass --op-item <id-or-name> or set OP_ITEM,\n"
            "     or set USE_OP = False at the top of this script to be prompted.", 3)

    key = passphrase()
    log("Key loaded")

    base = load(args.base, key)
    supp = load(args.supplement, key)
    log(f"base:       {len(base.get('records', []))} records, "
        f"{len(base.get('errors', []))} errors")
    log(f"supplement: {len(supp.get('records', []))} records, "
        f"{len(supp.get('errors', []))} errors")

    by_uid = {r["uid"]: r for r in base.get("records", [])}
    if len(by_uid) != len(base.get("records", [])):
        die("the base file has duplicate uids - refusing to guess")

    replaced, added, skipped = [], [], []
    for rec in supp.get("records", []):
        uid = rec["uid"]
        if uid not in by_uid:
            by_uid[uid] = rec
            added.append(uid)
        elif complete(rec) and not complete(by_uid[uid]):
            by_uid[uid] = rec
            replaced.append(uid)
        elif complete(rec):
            # Both complete: the supplement is newer, so prefer it.
            by_uid[uid] = rec
            replaced.append(uid)
        else:
            skipped.append(uid)

    fixed = set(replaced) | set(added)
    kept_errors = [e for e in base.get("errors", []) if e.get("uid") not in fixed]
    dropped = len(base.get("errors", [])) - len(kept_errors)

    still_stub = [u for u, r in by_uid.items() if not complete(r)]

    merged = {
        "meta": {
            **base.get("meta", {}),
            "merged_at": datetime.now(timezone.utc).isoformat(),
            "merged_from": [os.path.basename(args.base), os.path.basename(args.supplement)],
            "record_count": len(by_uid),
            "error_count": len(kept_errors),
            "records_replaced_by_supplement": len(replaced),
            "records_added_by_supplement": len(added),
            "records_still_incomplete": len(still_stub),
        },
        "records": sorted(by_uid.values(), key=lambda r: r["uid"]),
        "errors": kept_errors,
    }

    log(f"replaced {len(replaced)}, added {len(added)}, skipped {len(skipped)}")
    log(f"dropped {dropped} stale error entries")
    log(f"records without detail after merge: {len(still_stub)}")

    payload = json.dumps(merged, indent=2, ensure_ascii=False, default=str).encode()
    log(f"Encrypting {len(payload):,} bytes")
    p = with_passphrase(["--symmetric", "--cipher-algo", "AES256", "--s2k-mode", "3",
                         "--s2k-digest-algo", "SHA512", "--s2k-count", "65011712",
                         "--yes", "--output", args.output], key, payload)
    if p.returncode != 0:
        if os.path.exists(args.output):
            os.unlink(args.output)
        die(f"gpg failed: {p.stderr.decode(errors='replace')[:200]}", 5)
    os.chmod(args.output, 0o600)

    log(f"Wrote {args.output} ({os.path.getsize(args.output):,} bytes, mode 0600)")
    log("RESULT: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
