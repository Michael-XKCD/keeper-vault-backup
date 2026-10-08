# keeper-vault-backup

[![check](https://github.com/Michael-XKCD/keeper-vault-backup/actions/workflows/check.yml/badge.svg)](https://github.com/Michael-XKCD/keeper-vault-backup/actions/workflows/check.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)
![Licence](https://img.shields.io/badge/licence-MIT-green)

Export a Keeper vault - every record, with full revision history - to a single
encrypted JSON file.

Written because a password manager migration only carries across the *current*
value of each record. Revision history, TOTP seeds sitting on older record
types, and anything the importer skips are all lost the moment the old tenant is
switched off. This takes a copy first.

## What it captures

Per record:

| | |
|---|---|
| `listing` | uid, title, type, shared flag, category |
| `detail` | every field and custom field, TOTP seed, passkey, notes, attachment metadata |
| `history.revisions` | who changed it and when |
| `history.diff` | field-level old and new values |
| `history.revision_views` | the whole record reconstructed at each past revision (`--deep-history`) |

`diff` alone is not a complete history - it reports some field changes and
flattens others. `--deep-history` is the only way to get every value at every
revision. It costs one extra Commander call per revision per record.

## Requirements

- [Keeper Commander](https://github.com/Keeper-Security/Commander) - `keeper`, logged in
- [1Password CLI](https://developer.1password.com/docs/cli/) - `op`, holding the encryption passphrase
- `gpg`
- Python 3.9+

## Use

```bash
export OP_ITEM="My Backup Passphrase"     # 1Password item holding the passphrase
python3 scripts/keeper-full-backup.py --deep-history -o backup.json.gpg
```

Handy flags:

```
--limit N          only the first N records (try a small run first)
--only-uids FILE   restrict to uids listed in FILE, one per line
--no-history       skip history entirely - much faster
--chunk N          records per Commander session (default 200)
--dry-run          prove op + gpg work without touching Keeper
--check            print Keeper Commander login instructions
```

Records that fail are listed in the `errors` array inside the backup. Re-fetch
just those, then merge:

```bash
python3 scripts/keeper-full-backup.py --deep-history --only-uids failed.txt -o supplement.json.gpg
python3 scripts/keeper-merge-backup.py backup.json.gpg supplement.json.gpg -o merged.json.gpg
```

## Reading it back

```bash
gpg --decrypt merged.json.gpg | jq '.meta'
gpg --decrypt merged.json.gpg | jq -r '.records[].detail.title' | sort
gpg --decrypt merged.json.gpg | jq '.records[] | select(.detail.totp) | .detail.title'
```

## How secrets are handled

- The plaintext JSON is **never written to disk**. It is streamed into `gpg`'s stdin; only the encrypted file is created.
- The passphrase is read from 1Password and passed to `gpg` on an anonymous pipe by file descriptor - never in `argv` (visible to any local user via `ps`), never in an environment variable, never in a temp file.
- Output is symmetric AES-256 with a SHA-512, maximum-iteration S2K, and is integrity protected.
- The output file is created mode `0600`, and the tool refuses to overwrite an existing file or to write anything not ending in `.gpg`.

The backup contains every password and TOTP seed in the vault in plaintext once
decrypted. Treat the file accordingly, and do not redirect a decryption to disk
unless you mean to.

## Speed

Each `keeper --batch-mode` invocation re-syncs the whole vault, which costs
roughly a minute. On a vault of a few thousand records that worked out at roughly 65s per
command. Feeding many commands into a single `keeper shell` and splitting the
output on its prompt brings it to about 0.7s per command - 43 hours down to
about 90 minutes. `--deep-history` adds a few hours on top for a vault with
substantial history.

## Known Commander quirk

Keeper record uids are base64url, so some begin with `-`. Commander's argument
parser reads that as a flag. Options must come first, then `--`:

```bash
keeper --batch-mode "get --format json -- -ExampleRecordUid00001"   # works
keeper --batch-mode "get -ExampleRecordUid00001 --format json"      # fails
```

`keeper-full-backup.py` already does this. Worth knowing if you script Commander yourself.

## Tests

```bash
python3 -m pip install pytest
python3 -m pytest tests -q
```

They need no Keeper or 1Password access and touch no real vault. The gpg
round-trip tests skip automatically if `gpg` is not installed.

## Licence

MIT - see [LICENSE](LICENSE).
