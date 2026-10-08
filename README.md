# keeper-vault-backup

[![check](https://github.com/Michael-XKCD/keeper-vault-backup/actions/workflows/check.yml/badge.svg)](https://github.com/Michael-XKCD/keeper-vault-backup/actions/workflows/check.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)
![Licence](https://img.shields.io/badge/licence-MIT-green)

Back up a whole Keeper vault, with full revision history, to one encrypted JSON file.

Moving to a new password manager? The importer only brings over each record's
*current* value. Revision history, TOTP seeds on older record types, and anything
the importer skips are gone once Keeper is switched off. Take a copy first.

## What it captures

Per record:

| | |
|---|---|
| `listing` | uid, title, type, shared flag, category |
| `detail` | every field and custom field, TOTP seed, passkey, notes, attachment metadata |
| `history.revisions` | who changed it and when |
| `history.diff` | field-level old and new values |
| `history.revision_views` | the whole record at each past revision (`--deep-history`) |

`diff` alone misses some changes. Use `--deep-history` for every value at every
revision. It costs one extra Commander call per revision.

## Requirements

- [Keeper Commander](https://github.com/Keeper-Security/Commander) (`keeper`), logged in
- `gpg`
- Python 3.9+

## The passphrase

I was migrating to 1Password, so by default the scripts read the backup
passphrase from a 1Password item with the
[1Password CLI](https://developer.1password.com/docs/cli/) (`op`).

Not using 1Password? Set `USE_OP = False` at the top of both scripts. They will
ask you for the passphrase instead.

## Use

```bash
export OP_ITEM="My Backup Passphrase"     # only needed with USE_OP = True
python3 scripts/keeper-full-backup.py --deep-history -o backup.json.gpg
```

Handy flags:

```
--limit N          only the first N records (try a small run first)
--only-uids FILE   restrict to uids listed in FILE, one per line
--no-history       skip history entirely - much faster
--chunk N          records per Commander session (default 200)
--dry-run          prove the passphrase + gpg work without touching Keeper
--check            print Keeper Commander login instructions
```

Failed records are listed in the backup's `errors` array. Re-fetch just those,
then merge:

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

- **Plaintext never touches disk.** The JSON streams straight into `gpg`. Only the encrypted file is written.
- **The passphrase never shows in `ps`.** It reaches `gpg` over a private pipe, not as an argument, environment variable, or temp file.
- **Strong encryption.** AES-256 with maximum-strength SHA-512 key stretching, integrity protected.
- **Careful file handling.** The output is mode `0600`, never overwrites a file, and must end in `.gpg`.

Once decrypted, the backup holds every password and TOTP seed in plain text.
Pipe it, don't save it, unless you mean to.

## Speed

Each `keeper --batch-mode` call re-syncs the whole vault. On a vault of a few
thousand records that is about a minute per call. This script runs many
commands in one `keeper shell` instead, at about 0.7s each. That took a full
backup from 43 hours to about 90 minutes. `--deep-history` adds a few hours more.

## Known Commander quirk

Keeper uids can start with `-`, and Commander reads that as a flag. Put options
first, then `--`:

```bash
keeper --batch-mode "get --format json -- -ExampleRecordUid00001"   # works
keeper --batch-mode "get -ExampleRecordUid00001 --format json"      # fails
```

The script already does this. Good to know if you script Commander yourself.

## Tests

```bash
python3 -m pip install pytest
python3 -m pytest tests -q
```

No Keeper or password manager access needed. The gpg round-trip tests skip if
`gpg` is not installed.

## Licence

MIT - see [LICENSE](LICENSE).
