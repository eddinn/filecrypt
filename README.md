# filecrypt

Create, open, edit, and resave encrypted files using your normal editor.

`filecrypt` is a small command-line tool for encrypted notes and other text files. It opens plaintext in your editor, then writes the result back as an authenticated encrypted `.enc` file.

The current implementation is `filecrypt.py`, with `filecrypt.sh` kept as a thin compatibility wrapper that executes the Python CLI.

## Features

- AES-256-GCM authenticated encryption
- scrypt password-based key derivation
- RSA-OAEP-SHA256 support for certificate/private-key mode
- password-only, certificate-only, or password + certificate access
- authenticated file metadata
- private temporary edit directory with `0600` plaintext file permissions
- atomic encrypted writes
- editor selection through `$VISUAL`, then `$EDITOR`, then `vim`, then `vi`
- Vim/Vi launched with `-n` when auto-detected to reduce swap-file leakage
- refuses to silently open legacy OpenSSL-CBC `.enc` files

## Requirements

- Python 3.10+
- `cryptography`
- `vim`, `vi`, or another editor configured through `$VISUAL` or `$EDITOR`

Install Python dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Install

From the repo checkout:

```bash
chmod +x filecrypt.py filecrypt.sh
```

Optional local install:

```bash
install -m 755 filecrypt.py ~/.local/bin/filecrypt
```

Or keep using the shell wrapper from the repository:

```bash
./filecrypt.sh secret.txt
```

## Basic password usage

Create a new encrypted file from a new or existing plaintext name:

```bash
filecrypt notes.txt
```

This opens `notes.txt` in your editor and writes the encrypted file to:

```text
notes.txt.enc
```

Open, edit, and resave an existing encrypted file:

```bash
filecrypt notes.txt.enc
```

Encrypt an existing plaintext file without opening an editor:

```bash
filecrypt --encrypt-only notes.txt
```

Remove the plaintext source only after successful encryption:

```bash
filecrypt --encrypt-only --remove-plain notes.txt
```

Decrypt to stdout:

```bash
filecrypt --decrypt-to-stdout notes.txt.enc
```

## Certificate mode

Generate a local RSA key and self-signed certificate for testing:

```bash
openssl req -x509 -newkey rsa:4096 -keyout filecrypt.key -out filecrypt.crt -days 3650 -nodes -subj '/CN=filecrypt'
```

Create a certificate-only encrypted file:

```bash
filecrypt --cert filecrypt.crt secret.txt
```

Open, edit, and resave it with the private key:

```bash
filecrypt --key filecrypt.key secret.txt.enc
```

## Password + certificate mode

For new files, pass both `--password` and `--cert`:

```bash
filecrypt --password --cert filecrypt.crt secret.txt
```

To open it again, you need both the password and the private key:

```bash
filecrypt --key filecrypt.key secret.txt.enc
```

## Useful options

```text
--password              Require a password for new files; default unless --cert is used
--cert PATH             RSA X.509 certificate or RSA public key PEM for new files
--key PATH              RSA private key PEM for opening cert/both encrypted files
--password-stdin        Read file password from stdin; useful for scripts/tests
--key-password-stdin    Read encrypted private-key password from stdin
--scrypt-n N            scrypt CPU/memory cost for new password files
--ext EXT               Extension for new encrypted files; default: .enc
--encrypt-only          Encrypt existing plaintext without opening the editor
--decrypt-to-stdout     Decrypt an existing filecrypt v2 file to stdout
--remove-plain          Remove plaintext source after successful encryption
```

## Legacy OpenSSL `.enc` files

Older versions of this repo used `openssl enc -aes-256-cbc -pbkdf2`. Those files are not filecrypt v2 files.

The v2 tool intentionally refuses to silently decrypt legacy OpenSSL-CBC `.enc` files. Decrypt them once with the old script or OpenSSL, then re-encrypt with this version.

Manual legacy decrypt example:

```bash
openssl enc -aes-256-cbc -pbkdf2 -d -a -in oldfile.txt.enc -out oldfile.txt
```

Then re-encrypt with filecrypt v2:

```bash
filecrypt --encrypt-only --remove-plain oldfile.txt
```

## Security notes

This tool is much safer than the old OpenSSL-CBC wrapper, but it is not magic.

Temporary plaintext is still plaintext. The tool writes it in a private temporary directory with restrictive permissions and removes it when the editor exits, but leaks are still possible through:

- editor swap files
- editor backup files
- filesystem journals
- crash dumps
- terminal scrollback
- editor plugins
- malware or another user with elevated privileges

For higher paranoia, use a tmpfs-backed temp directory:

```bash
TMPDIR=/dev/shm filecrypt secret.txt.enc
```

Vim/Vi is launched with `-n` when auto-detected to avoid swap files. Your editor config can still create backups. Check your config instead of trusting vibes.

Certificate mode currently supports RSA certificates/keys only.

Use a real passphrase. `password123` is not encryption; it is a gift basket for attackers.

## Smoke tests

Run the included smoke tests:

```bash
python3 tests/smoke_test.py
```

The tests cover password mode and RSA certificate mode.

## License

MIT
