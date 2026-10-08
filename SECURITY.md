# Security policy

## Reporting a vulnerability

Please report security issues privately using GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository, rather than opening a public issue.

This is a small personal project, so there is no formal response-time
commitment. Security reports are the one category that always gets looked at.

## Scope

Both scripts in `scripts/` are in scope: the Keeper export and the merge
tool. Reports about the encryption of the output file, how the passphrase is
handled, or anything that could put vault plaintext on disk are especially
wanted.

## What this tool is trusted with

It reads an entire password vault and writes it, encrypted, to one file. It
holds the decrypted vault in memory for the duration of a run, and holds the
encryption passphrase in memory. It never writes plaintext to disk and never
puts the passphrase in `argv` or the environment - if you find a path where
either is untrue, that is a valid report.
