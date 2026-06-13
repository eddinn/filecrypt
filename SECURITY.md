# Security notes

## What v2 protects

- File contents are encrypted with AES-256-GCM.
- The metadata header is authenticated as additional data.
- Password files use scrypt with per-file random salt.
- Certificate files use RSA-OAEP-SHA256 wrapping.
- Password + certificate mode requires both the password and RSA private key.
- Writes are atomic and encrypted files are created with `0600` permissions.

## What v2 cannot fully protect

Editing requires plaintext to exist briefly. The tool creates it under a private temporary directory and removes it when the editor exits, but crashes, filesystem journals, editor backups, swap files, plugins, terminal scrollback, and malware can still leak plaintext.

For better local hygiene:

```bash
TMPDIR=/dev/shm filecrypt secret.txt.enc
```

Also check your editor config. Vim is launched with `-n` when auto-detected, but your vimrc can still create backups/undo files elsewhere.

## Legacy `.enc` files

The old OpenSSL-CBC format is not silently supported. Decrypt old files once with the original script/OpenSSL, then re-encrypt with this version.
