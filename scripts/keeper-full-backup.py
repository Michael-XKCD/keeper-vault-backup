#!/usr/bin/env python3
"""Export every Keeper record you can see - with history - to an encrypted JSON file.

Why this exists
---------------
Written for a Keeper migration. A password-manager importer takes the current value of
a record and nothing else: no revision history, no TOTP seed on a V2 "general"
record, no passkey. Once the tenant is gone, that material is gone. This pulls
everything Commander will hand over and seals it in one file.

What it captures, per record
----------------------------
  listing  - what `list` knows: uid, title, type, shared flag, category
  detail   - the full record from `get`: every field, custom field, TOTP/OTP
             seed, passkey, notes, attachment metadata
  history  - every revision `record-history` will return

Secret handling
---------------
The plaintext JSON is NEVER written to disk. It is streamed straight into gpg's
stdin, and only the encrypted file is created. The passphrase comes from
1Password (or a prompt - see USE_OP) and is passed to gpg on an anonymous pipe
by file descriptor, so it never appears in argv (visible to any user via `ps`), in an environment
variable, or in a temp file.

The output is symmetric AES-256 with a SHA-512 / high-iteration S2K. Decrypt it
with the same passphrase:

    gpg --decrypt keeper-backup-<stamp>.json.gpg | jq '.meta'

Redirecting that to a file writes every password and TOTP seed in the vault to
disk in the clear. Pipe it instead unless you really mean to.

Requires an unlocked Keeper Commander session - see --check.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

# Where the passphrase comes from. I was migrating to 1Password, so by default it
# is read with the 1Password CLI (`op`). Set USE_OP = False to type it at a
# prompt instead - no password manager needed.
USE_OP = True

# The 1Password item holding the passphrase. Override with --op-item / --op-field,
# or the OP_ITEM / OP_FIELD environment variables, so nothing site-specific is
# baked into the source.
OP_ITEM = os.environ.get("OP_ITEM", "")
OP_FIELD = os.environ.get("OP_FIELD", "password")

KEEPER = "keeper"
GPG = "gpg"
OP = "op"

# Commander refuses almost every command without a session and says so on stdout
# rather than failing loudly, so detect that text explicitly.
NO_SESSION = "persistent login is not working"


def log(msg: str) -> None:
    print(f"[keeper-backup] {msg}", file=sys.stderr, flush=True)


def die(msg: str, code: int = 1) -> "typing.NoReturn":  # noqa: F821
    print(f"[keeper-backup] ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def keeper(command: str, timeout: int = 180) -> tuple[bool, str]:
    """Run one Commander command. Returns (ok, stdout).

    Commander exits 0 while printing an error for a locked session, so the
    caller cannot trust the exit code alone.
    """
    try:
        proc = subprocess.run(
            [KEEPER, "--batch-mode", command],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout}s"
    out = (proc.stdout or "") + (proc.stderr or "")
    if NO_SESSION in out.lower():
        return False, "no Keeper session"
    return proc.returncode == 0, out


def parse_json(text: str):
    """Commander prefixes JSON with progress lines often enough to be worth it."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for opener, closer in (("[", "]"), ("{", "}")):
        start, end = text.find(opener), text.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                continue
    return None


def require_session() -> str:
    ok, out = keeper("whoami")
    if not ok:
        die("Keeper Commander is not unlocked in this environment.\n"
            "     Run:  keeper shell     then  whoami     then re-run this script.\n"
            "     See --check for the full instructions.", 2)
    user = ""
    for line in out.splitlines():
        if "User:" in line:
            user = line.split("User:", 1)[1].strip()
            break
    return user or "unknown"


def prompt_passphrase() -> str:
    """Ask twice: a typo here would lock you out of the backup."""
    key = getpass.getpass("Backup passphrase: ")
    if not key:
        die("the passphrase is empty", 3)
    if getpass.getpass("Repeat it: ") != key:
        die("the passphrases do not match", 3)
    return key


def get_passphrase() -> str:
    if not USE_OP:
        return prompt_passphrase()
    try:
        proc = subprocess.run(
            [OP, "item", "get", OP_ITEM, "--fields", f"label={OP_FIELD}", "--reveal"],
            capture_output=True, text=True, timeout=60,
        )
    except FileNotFoundError:
        die("the 1Password CLI (op) is not installed", 3)
    except subprocess.TimeoutExpired:
        die("timed out reading the key from 1Password - is the app unlocked?", 3)
    if proc.returncode != 0:
        die(f"could not read the key from 1Password item {OP_ITEM}.\n"
            f"     {proc.stderr.strip()}\n"
            "     1Password must be unlocked with the CLI integration on.", 3)
    key = proc.stdout.strip()
    if not key:
        die(f"1Password returned an empty key for item {OP_ITEM} field '{OP_FIELD}'", 3)
    return key


def list_records() -> list[dict]:
    ok, out = keeper("list --format json")
    if not ok:
        die(f"`list` failed: {out.strip()[:200]}", 4)
    data = parse_json(out)
    if data is None:
        die("could not parse `list --format json` output", 4)
    if isinstance(data, dict):
        for key in ("records", "record_uid", "data"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
    if not isinstance(data, list):
        die("`list` did not return an array of records", 4)
    return data


def uid_of(rec: dict) -> str | None:
    for key in ("record_uid", "uid", "recordUid", "record_id"):
        if rec.get(key):
            return str(rec[key])
    return None


PROMPT = "My Vault> "


def run_batch(commands: list[str], timeout: int = 3600) -> list[object | None]:
    """Run many commands in ONE `keeper shell` and return one result per command.

    Every `keeper --batch-mode` invocation re-syncs the whole vault, which costs
    roughly a minute. Measured: 65s per command that way, 0.68s
    per command through a single shell - the difference between 43 hours and 90
    minutes for a full export.

    Output is NOT written to files. `get` ignores --output, and the alternatives
    (`export` to a path, `record-history --output`) would put unencrypted
    secrets on disk, which is the one thing this script promises not to do. So
    the shell's stdout is captured and split on its prompt.

    Returns a list positionally matching `commands`; an entry is None when that
    command produced no parseable JSON (an error, or an empty history).
    """
    script = "".join(c + "\n" for c in commands) + "quit\n"
    try:
        proc = subprocess.run([KEEPER, "shell"], input=script,
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [None] * len(commands)
    if NO_SESSION in (proc.stdout + proc.stderr).lower():
        die("the Keeper session dropped mid-run (a VPN or network change will do "
            "this). Log in again and re-run - see --check.", 2)

    # The banner precedes the first prompt, so segment[0] is discarded and each
    # later segment is the output of one command, in order.
    segments = proc.stdout.split(PROMPT)[1:]
    results: list[object | None] = []
    for i in range(len(commands)):
        if i >= len(segments):
            results.append(None)
            continue
        results.append(parse_json(segments[i]))
    return results


def encrypt_to(path: str, payload: bytes, passphrase: str) -> None:
    """Stream payload into gpg. Plaintext never touches the filesystem."""
    read_fd, write_fd = os.pipe()
    os.set_inheritable(read_fd, True)
    try:
        with os.fdopen(write_fd, "w") as w:
            w.write(passphrase)
        proc = subprocess.run(
            [GPG, "--symmetric", "--cipher-algo", "AES256",
             "--s2k-mode", "3", "--s2k-digest-algo", "SHA512",
             "--s2k-count", "65011712",
             "--batch", "--yes", "--quiet", "--pinentry-mode", "loopback",
             "--passphrase-fd", str(read_fd), "--output", path],
            input=payload, capture_output=True, pass_fds=(read_fd,),
        )
    finally:
        try:
            os.close(read_fd)
        except OSError:
            pass
    if proc.returncode != 0:
        if os.path.exists(path):
            os.unlink(path)
        die(f"gpg failed: {proc.stderr.decode(errors='replace').strip()[:300]}", 5)
    os.chmod(path, 0o600)


def print_check() -> None:
    print("""
Unlocking Keeper Commander for a scripted run
=============================================

Commander keeps a session in ~/.keeper/config.json. A non-interactive shell
cannot complete an SSO device approval, so YOU log in once in a terminal and the
script then reuses that session.

1. Open a terminal and start the shell:

       keeper shell

2. If it does not log you in automatically:

       login you@example.com

   It prints an SSO URL and a short menu.
     - type  o  and press Return   (opens the login page in your browser)
     - sign in, then click "Copy login token"
     - type  p  and press Return   (pastes the token back)

   If it asks to approve the device, keep the Keeper DESKTOP app open and
   unlocked, choose 1 (Keeper Push), approve the notification, then type r.

3. Make the session survive the shell exiting:

       this-device persistent-login on
       this-device ip-auto-approve on

4. Confirm, then leave the shell:

       whoami
       quit

5. Verify from a plain shell - this must print your account, not an error:

       keeper --batch-mode whoami

Two things that break it:
  - A network/location change (VPN on or off) invalidates the session. Log in
    again from the same network you will run the backup on.
  - With USE_OP on, 1Password must also be unlocked, with Settings > Developer >
    "Integrate with 1Password CLI" turned on, so the script can read the
    encryption key.
""".strip())


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Encrypted full-history export of every Keeper record you can see.")
    ap.add_argument("-o", "--output", help="output path (default: ./keeper-backup-<stamp>.json.gpg)")
    ap.add_argument("--limit", type=int, help="only process the first N records (for testing)")
    ap.add_argument("--only-uids", metavar="FILE",
                    help="restrict the run to the record uids listed in FILE, one per "
                         "line - used to re-fetch records a previous run failed on")
    ap.add_argument("--no-history", action="store_true", help="skip revision history (much faster)")
    ap.add_argument("--chunk", type=int, default=200,
                    help="records per Commander session (default 200)")
    ap.add_argument("--deep-history", action="store_true",
                    help="also reconstruct each record at every past revision "
                         "(one extra call per revision - slow, but complete)")
    ap.add_argument("--dry-run", action="store_true",
                    help="run everything except Keeper: prove the passphrase + gpg work end to end")
    ap.add_argument("--op-item", help="1Password item id or name holding the passphrase "
                                     "(or set OP_ITEM)")
    ap.add_argument("--op-field", help="field on that item (default: password, or OP_FIELD)")
    ap.add_argument("--check", action="store_true", help="print Keeper unlock instructions and exit")
    args = ap.parse_args()

    if args.check:
        print_check()
        return 0

    global OP_ITEM, OP_FIELD
    if args.op_item:
        OP_ITEM = args.op_item
    if args.op_field:
        OP_FIELD = args.op_field
    if USE_OP and not OP_ITEM:
        die("no 1Password item given. Pass --op-item <id-or-name> or set OP_ITEM.\n"
            "     The item must hold the passphrase used to encrypt the backup.\n"
            "     Or set USE_OP = False at the top of this script to be prompted.", 3)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = args.output or f"keeper-backup-{stamp}.json.gpg"
    if os.path.exists(out_path):
        die(f"{out_path} already exists - refusing to overwrite")
    if not out_path.endswith(".gpg"):
        die("output path must end in .gpg - this file is always encrypted")

    log("Reading the encryption key from 1Password" if USE_OP else "Asking for the encryption key")
    passphrase = get_passphrase()
    log("Key loaded (never written to disk, never in argv)")

    if args.dry_run:
        payload = json.dumps({"meta": {"dry_run": True, "generated_at": stamp}},
                             indent=2).encode()
        encrypt_to(out_path, payload, passphrase)
        log(f"Dry run wrote {out_path} ({os.path.getsize(out_path)} bytes)")
        log("RESULT: ok")
        return 0

    user = require_session()
    log(f"Keeper session: {user}")

    log("Listing records")
    listing = list_records()
    if args.only_uids:
        with open(args.only_uids) as f:
            wanted = {l.strip() for l in f if l.strip()}
        listing = [r for r in listing if uid_of(r) in wanted]
        missing = wanted - {uid_of(r) for r in listing}
        log(f"--only-uids: {len(listing)} of {len(wanted)} requested uids found in the vault")
        if missing:
            log(f"  not present any more: {sorted(missing)}")
    if args.limit:
        listing = listing[: args.limit]
    log(f"{len(listing)} records to export")

    records, errors = [], []
    started = time.time()
    want_history = not args.no_history
    per_record = 3 if want_history else 1

    # Chunked so a dropped session costs one chunk, not the whole run, and so
    # progress is visible on a vault this size.
    chunk = max(1, args.chunk)
    for start in range(0, len(listing), chunk):
        batch = listing[start:start + chunk]
        uids, valid = [], []
        for rec in batch:
            uid = uid_of(rec)
            if not uid:
                errors.append({"stage": "uid", "record": rec, "error": "no uid field"})
                continue
            uids.append(uid)
            valid.append(rec)

        commands = []
        for uid in uids:
            commands.append(f"get --format json -- {uid}")
            if want_history:
                commands.append(f"record-history --format json -- {uid}")
                commands.append(f"record-history --format json -a diff -- {uid}")

        results = run_batch(commands)

        for n, (uid, rec) in enumerate(zip(uids, valid)):
            base = n * per_record
            entry = {"uid": uid, "listing": rec}
            detail = results[base] if base < len(results) else None
            if detail is None:
                errors.append({"stage": "get", "uid": uid, "error": "no JSON returned"})
            else:
                # Positional mapping is only safe if the payload is the record we
                # asked for; a mismatch means the stream drifted.
                got = detail.get("record_uid") if isinstance(detail, dict) else None
                if got and got != uid:
                    errors.append({"stage": "get", "uid": uid,
                                   "error": f"response drift: got {got}"})
                else:
                    entry["detail"] = detail
            if want_history:
                hist = {}
                revs = results[base + 1] if base + 1 < len(results) else None
                diff = results[base + 2] if base + 2 < len(results) else None
                if revs is not None:
                    hist["revisions"] = revs
                if diff is not None:
                    hist["diff"] = diff
                if hist:
                    entry["history"] = hist
                else:
                    errors.append({"stage": "history", "uid": uid,
                                   "error": "no history returned"})
            records.append(entry)

        done = min(start + chunk, len(listing))
        rate = (time.time() - started) / max(1, done)
        left = (len(listing) - done) * rate
        log(f"  {done}/{len(listing)} ({time.time() - started:.0f}s elapsed, "
            f"~{left / 60:.0f}m left)")

    if args.deep_history and want_history:
        log("Fetching per-revision views (--deep-history)")
        for i, entry in enumerate(records, 1):
            revs = entry.get("history", {}).get("revisions")
            count = len(revs) if isinstance(revs, list) else 0
            if count < 2:
                continue
            cmds = [f"record-history --format json -a view -r {n} -- {entry['uid']}"
                    for n in range(1, count)]
            views = run_batch(cmds)
            got = {str(n): v for n, v in enumerate(views, 1) if v is not None}
            if got:
                entry["history"]["revision_views"] = got
            if i % 25 == 0:
                log(f"  deep {i}/{len(records)}")

    doc = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "keeper_user": user,
            "record_count": len(records),
            "error_count": len(errors),
            "history_included": not args.no_history,
            "deep_history": bool(args.deep_history),
            "source": "keeper commander",
            "note": "Contains plaintext secrets, TOTP seeds and passkeys. Keep encrypted.",
        },
        "records": records,
        "errors": errors,
    }
    payload = json.dumps(doc, indent=2, ensure_ascii=False, default=str).encode()
    log(f"Encrypting {len(payload):,} bytes of JSON")
    encrypt_to(out_path, payload, passphrase)

    log(f"Wrote {out_path} ({os.path.getsize(out_path):,} bytes, mode 0600)")
    if errors:
        log(f"{len(errors)} records had a problem - see the 'errors' array inside")
    log("RESULT: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
