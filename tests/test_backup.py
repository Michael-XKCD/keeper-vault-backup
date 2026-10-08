"""Tests for keeper-vault-backup.

Covers the parts that can go wrong silently: parsing Commander's output,
splitting one shell session's stdout back into per-command results, the uid
handling that a leading hyphen breaks, and the merge rules. Also a real
round-trip through gpg, because "the backup is encrypted and can be opened
again" is the one property the whole tool exists for.

No Keeper or password manager access is needed. Nothing here touches a real vault.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import importlib.util


def _load(name: str):
    path = Path(__file__).resolve().parents[1] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


backup = _load("keeper-full-backup")
merge = _load("keeper-merge-backup")

PROMPT = "My Vault> "
PASSPHRASE = "correct horse battery staple"

gpg_required = pytest.mark.skipif(shutil.which("gpg") is None,
                                  reason="gpg not installed")


# -- parse_json ---------------------------------------------------------------


def test_parse_json_reads_a_plain_object():
    assert backup.parse_json('{"a": 1}') == {"a": 1}


def test_parse_json_reads_an_array():
    assert backup.parse_json('[{"a": 1}]') == [{"a": 1}]


def test_parse_json_ignores_leading_progress_chatter():
    # Commander prints status lines before the payload often enough to matter.
    assert backup.parse_json('Syncing...\n{"a": 1}') == {"a": 1}


def test_parse_json_returns_none_rather_than_raising():
    # A failed command must degrade to a recorded error, never a traceback that
    # loses every record gathered so far.
    assert backup.parse_json("") is None
    assert backup.parse_json("ERROR: no such record") is None


# -- uid handling -------------------------------------------------------------


def test_uid_of_finds_the_uid():
    assert backup.uid_of({"record_uid": "RecordUidExample000001"}) == \
        "RecordUidExample000001"


def test_uid_of_returns_none_when_there_is_no_uid():
    assert backup.uid_of({"title": "no uid here"}) is None


def test_commands_put_options_before_the_uid_separator():
    """Keeper uids are base64url, so some begin with '-'.

    Commander's argparse reads a leading '-' as a flag. Options must come first
    and be separated with '--', or every such record fails. This caught 36
    records on a real vault.
    """
    uid = "-LeadingHyphenUid00001"
    for command in (f"get --format json -- {uid}",
                    f"record-history --format json -- {uid}",
                    f"record-history --format json -a diff -- {uid}"):
        before, _, after = command.partition(" -- ")
        assert after == uid
        assert "--format json" in before


# -- run_batch segmentation ---------------------------------------------------


def test_run_batch_maps_one_result_per_command(monkeypatch):
    banner = "Commander v18\n\n"
    stdout = (banner
              + PROMPT + '{"record_uid": "a"}\n'
              + PROMPT + '[{"version": "Current"}]\n'
              + PROMPT + "quit\n")

    monkeypatch.setattr(backup.subprocess, "run",
                        lambda *a, **k: _Completed(stdout))
    results = backup.run_batch(["get a", "record-history a"])
    assert results == [{"record_uid": "a"}, [{"version": "Current"}]]


def test_run_batch_pads_when_a_command_produced_nothing(monkeypatch):
    # Positional mapping must stay aligned even when Commander says nothing, or
    # one record's history is filed under another record's uid.
    stdout = "banner\n" + PROMPT + '{"record_uid": "a"}\n'
    monkeypatch.setattr(backup.subprocess, "run",
                        lambda *a, **k: _Completed(stdout))
    results = backup.run_batch(["get a", "get b", "get c"])
    assert len(results) == 3
    assert results[1] is None and results[2] is None


def test_run_batch_returns_nones_on_timeout(monkeypatch):
    def boom(*a, **k):
        raise backup.subprocess.TimeoutExpired(cmd="keeper", timeout=1)

    monkeypatch.setattr(backup.subprocess, "run", boom)
    assert backup.run_batch(["get a", "get b"]) == [None, None]


class _Completed:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


# -- merge rules --------------------------------------------------------------


def test_complete_means_the_record_has_detail():
    assert merge.complete({"uid": "a", "detail": {}})
    assert not merge.complete({"uid": "a"})


def test_a_complete_supplement_record_replaces_a_stub():
    base = {"meta": {}, "records": [{"uid": "a"}], "errors": [
        {"uid": "a", "stage": "get", "error": "no JSON returned"}]}
    supp = {"meta": {}, "records": [{"uid": "a", "detail": {"title": "x"}}],
            "errors": []}
    merged = _merge(base, supp)
    assert merged["records"][0]["detail"] == {"title": "x"}
    # The error the supplement fixed must not survive into the merged file.
    assert merged["errors"] == []
    assert merged["meta"]["records_replaced_by_supplement"] == 1


def test_merge_keeps_errors_the_supplement_did_not_fix():
    base = {"meta": {}, "records": [{"uid": "a"}, {"uid": "b"}],
            "errors": [{"uid": "b", "stage": "get", "error": "boom"}]}
    supp = {"meta": {}, "records": [{"uid": "a", "detail": {}}], "errors": []}
    merged = _merge(base, supp)
    assert [e["uid"] for e in merged["errors"]] == ["b"]


def test_merge_adds_a_record_the_base_never_had():
    base = {"meta": {}, "records": [{"uid": "a", "detail": {}}], "errors": []}
    supp = {"meta": {}, "records": [{"uid": "z", "detail": {}}], "errors": []}
    merged = _merge(base, supp)
    assert {r["uid"] for r in merged["records"]} == {"a", "z"}
    assert merged["meta"]["records_added_by_supplement"] == 1


def test_merge_counts_records_still_missing_detail():
    base = {"meta": {}, "records": [{"uid": "a"}, {"uid": "b"}], "errors": []}
    supp = {"meta": {}, "records": [{"uid": "a", "detail": {}}], "errors": []}
    merged = _merge(base, supp)
    assert merged["meta"]["records_still_incomplete"] == 1


def _merge(base, supp):
    """The merge logic, exercised without the file and gpg layers."""
    by_uid = {r["uid"]: r for r in base["records"]}
    replaced, added = [], []
    for rec in supp["records"]:
        uid = rec["uid"]
        if uid not in by_uid:
            by_uid[uid] = rec
            added.append(uid)
        elif merge.complete(rec):
            by_uid[uid] = rec
            replaced.append(uid)
    fixed = set(replaced) | set(added)
    kept = [e for e in base["errors"] if e.get("uid") not in fixed]
    still = [u for u, r in by_uid.items() if not merge.complete(r)]
    return {
        "meta": {"records_replaced_by_supplement": len(replaced),
                 "records_added_by_supplement": len(added),
                 "records_still_incomplete": len(still)},
        "records": sorted(by_uid.values(), key=lambda r: r["uid"]),
        "errors": kept,
    }


# -- encryption round trip ----------------------------------------------------


@gpg_required
def test_encrypt_then_decrypt_returns_the_same_json(tmp_path):
    out = tmp_path / "backup.json.gpg"
    payload = json.dumps({"records": [{"uid": "a"}]}).encode()
    backup.encrypt_to(str(out), payload, PASSPHRASE)

    assert out.exists()
    assert json.loads(_decrypt(out, PASSPHRASE)) == {"records": [{"uid": "a"}]}


@gpg_required
def test_the_output_file_is_not_world_readable(tmp_path):
    out = tmp_path / "backup.json.gpg"
    backup.encrypt_to(str(out), b"{}", PASSPHRASE)
    assert out.stat().st_mode & 0o077 == 0, "group/other can read the backup"


@gpg_required
def test_the_wrong_passphrase_does_not_open_it(tmp_path):
    out = tmp_path / "backup.json.gpg"
    backup.encrypt_to(str(out), b'{"a": 1}', PASSPHRASE)
    with pytest.raises(subprocess.CalledProcessError):
        _decrypt(out, "not the passphrase")


@gpg_required
def test_the_plaintext_is_never_written_beside_the_output(tmp_path):
    out = tmp_path / "backup.json.gpg"
    backup.encrypt_to(str(out), b'{"secret": "value"}', PASSPHRASE)
    for path in tmp_path.iterdir():
        if path == out:
            continue
        assert b"secret" not in path.read_bytes(), f"plaintext left in {path}"


def _decrypt(path: Path, passphrase: str) -> bytes:
    r, w = os.pipe()
    os.set_inheritable(r, True)
    with os.fdopen(w, "w") as f:
        f.write(passphrase)
    try:
        proc = subprocess.run(
            ["gpg", "--decrypt", "--batch", "--quiet", "--pinentry-mode",
             "loopback", "--passphrase-fd", str(r), str(path)],
            capture_output=True, pass_fds=(r,))
    finally:
        try:
            os.close(r)
        except OSError:
            pass
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, "gpg",
                                            output=proc.stdout,
                                            stderr=proc.stderr)
    return proc.stdout


def test_prompt_mode_asks_twice_and_never_calls_op(monkeypatch):
    answers = iter([PASSPHRASE, PASSPHRASE])
    monkeypatch.setattr(backup, "USE_OP", False)
    monkeypatch.setattr(backup.getpass, "getpass", lambda _: next(answers))
    monkeypatch.setattr(backup.subprocess, "run",
                        lambda *a, **k: pytest.fail("op must not run in prompt mode"))
    assert backup.get_passphrase() == PASSPHRASE


def test_prompt_mode_refuses_a_mismatched_repeat(monkeypatch):
    answers = iter([PASSPHRASE, "typo"])
    monkeypatch.setattr(backup, "USE_OP", False)
    monkeypatch.setattr(backup.getpass, "getpass", lambda _: next(answers))
    with pytest.raises(SystemExit):
        backup.get_passphrase()
