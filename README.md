# filecrypt

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/7806ddad2525415f86ebffbe28e6defd)](https://www.codacy.com/manual/Eddinn/filecrypt?utm_source=github.com&utm_medium=referral&utm_content=eddinn/filecrypt&utm_campaign=Badge_Grade) [![CircleCI](https://circleci.com/gh/eddinn/filecrypt.svg?style=svg)](https://circleci.com/gh/eddinn/filecrypt) ![GitHub issues](https://img.shields.io/github/issues/eddinn/filecrypt) ![GitHub](https://img.shields.io/github/license/eddinn/filecrypt)

Create, open, edit, and resave encrypted files using your normal editor.

## Current status

The original `filecrypt.sh` script is a small legacy wrapper around `openssl enc -aes-256-cbc -pbkdf2`. It works for basic password-encrypted notes, but it should be treated as legacy.

Known issues in the legacy script:

- It hardcodes `vim` instead of respecting `$VISUAL`, `$EDITOR`, or the system default editor.
- It decrypts into a fixed `tmpfile.txt` in the current directory.
- It removes files with `rm -Rf`, which is overkill and risky for this job.
- It uses AES-256-CBC through `openssl enc`, which does not provide modern authenticated encryption.
- It has no file format metadata, versioning, or clean migration path.

In plain English: it is useful, but it is not where this tool should stay.

## Recommended v2 design

The secure replacement should use a self-describing encrypted file format and a small CLI that supports:

- AES-256-GCM for authenticated encryption
- scrypt for password-based keys
- RSA-OAEP-SHA256 wrapping for certificate/private-key mode
- password-only, certificate-only, or password + certificate encryption
- authenticated file metadata
- secure temporary directories and `0600` file permissions
- `$VISUAL`, then `$EDITOR`, then `vim`, then `vi`
- atomic encrypted writes
- no fixed plaintext temp filename

## Target v2 install

After applying the v2 implementation:

```bash
python3 -m pip install -r requirements.txt
chmod +x filecrypt.py filecrypt.sh
```

Optional local install:

```bash
install -m 755 filecrypt.py ~/.local/bin/filecrypt
```

## Target v2 password usage

Create or edit `notes.txt.enc`:

```bash
filecrypt notes.txt
```

Open, edit, and resave an existing encrypted file:

```bash
filecrypt notes.txt.enc
```

Encrypt an existing plaintext file without opening an editor:

```bash
filecrypt --encrypt-only notes.txt
```

Delete the plaintext source only after successful encryption:

```bash
filecrypt --encrypt-only --remove-plain notes.txt
```

## Target v2 certificate mode

Generate a local RSA key and self-signed certificate for testing:

```bash
openssl req -x509 -newkey rsa:4096 -keyout filecrypt.key -out filecrypt.crt -days 3650 -nodes -subj '/CN=filecrypt'
```

Create a cert-only encrypted file:

```bash
filecrypt --cert filecrypt.crt secret.txt
```

Open, edit, and resave it:

```bash
filecrypt --key filecrypt.key secret.txt.enc
```

## Target v2 password + certificate mode

For new files, pass both `--password` and `--cert`:

```bash
filecrypt --password --cert filecrypt.crt secret.txt
```

To open it again, you need both the password and the private key:

```bash
filecrypt --key filecrypt.key secret.txt.enc
```

## Legacy usage

The current legacy shell script still supports the original workflow:

```bash
./filecrypt.sh notes.txt
./filecrypt.sh notes.txt.enc
```

This will prompt through OpenSSL, open the plaintext in Vim, and write back an encrypted `.enc` file.

## Migrating old `.enc` files

Existing OpenSSL-CBC `.enc` files should not be silently auto-decrypted by the v2 tool. Decrypt them once with the legacy script or OpenSSL, then re-encrypt with the v2 format.

Manual legacy decrypt example:

```bash
openssl enc -aes-256-cbc -pbkdf2 -d -a -in oldfile.txt.enc -out oldfile.txt
```

Then re-encrypt with v2:

```bash
filecrypt --encrypt-only --remove-plain oldfile.txt
```

## Security notes and limits

- Temporary plaintext is still plaintext. Secure temp directories reduce exposure, but editor swap files, backups, filesystem journals, terminal scrollback, crash dumps, and plugins can still leak content.
- Vim should be launched with `-n` when auto-detected to avoid swap files. Your own editor config can still create backups.
- For higher paranoia, point `TMPDIR` at tmpfs, for example `/dev/shm`.
- Certificate mode should initially support RSA certificates/keys only unless the implementation explicitly adds more key types.
- If password mode is used, use a real passphrase. `password123` is not encryption; it is a donation to attackers.

## Smoke tests for v2

After applying the v2 implementation:

```bash
python3 tests/smoke_test.py
```
