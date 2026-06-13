#!/usr/bin/env python3
"""
filecrypt v2 - edit encrypted text files safely-ish.

File format: FCRYPT2\0 + uint32(header JSON length) + header JSON + AES-GCM ciphertext.
"""
from __future__ import annotations

import argparse
import base64
import copy
import getpass
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as exc:  # pragma: no cover - exercised by users without deps
    print(
        "filecrypt requires the Python 'cryptography' package.\n"
        "Install it with: python3 -m pip install cryptography",
        file=sys.stderr,
    )
    raise SystemExit(2) from exc

MAGIC = b"FCRYPT2\0"
VERSION = 2
DEFAULT_EXT = ".enc"
DEFAULT_SCRYPT_N = 2**16  # ~64 MiB with r=8. Increase for slower, stronger password files.
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
MAX_HEADER_LEN = 128 * 1024
MAX_SCRYPT_N = 2**20


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def json_bytes(header: dict[str, Any]) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def pack_file(header: dict[str, Any], ciphertext: bytes) -> bytes:
    hdr = json_bytes(header)
    if len(hdr) > MAX_HEADER_LEN:
        raise ValueError("header is too large")
    return MAGIC + len(hdr).to_bytes(4, "big") + hdr + ciphertext


def unpack_file(data: bytes) -> tuple[dict[str, Any], bytes, bytes]:
    if not data.startswith(MAGIC):
        raise ValueError("not a filecrypt v2 file")
    if len(data) < len(MAGIC) + 4:
        raise ValueError("truncated filecrypt header")
    hlen = int.from_bytes(data[len(MAGIC) : len(MAGIC) + 4], "big")
    if hlen <= 0 or hlen > MAX_HEADER_LEN:
        raise ValueError("invalid filecrypt header length")
    start = len(MAGIC) + 4
    end = start + hlen
    if len(data) < end:
        raise ValueError("truncated filecrypt header")
    header = json.loads(data[start:end].decode("utf-8"))
    aad = data[:end]
    return header, data[end:], aad


def is_filecrypt(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(len(MAGIC)) == MAGIC
    except FileNotFoundError:
        return False


def validate_scrypt_params(params: dict[str, Any]) -> tuple[bytes, int, int, int]:
    salt = b64d(params["salt"])
    n = int(params["n"])
    r = int(params["r"])
    p = int(params["p"])
    if n < 2 or n > MAX_SCRYPT_N or n & (n - 1):
        raise ValueError(f"invalid scrypt n={n}; expected power of 2 between 2 and {MAX_SCRYPT_N}")
    if r < 1 or r > 64 or p < 1 or p > 16:
        raise ValueError("invalid scrypt r/p parameters")
    return salt, n, r, p


def scrypt_key(password: bytes, params: dict[str, Any]) -> bytes:
    salt, n, r, p = validate_scrypt_params(params)
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(password)


def hkdf_key(material: bytes, salt: bytes, mode: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=f"filecrypt-v2 aes-256-gcm data key {mode}".encode("ascii"),
    )
    return hkdf.derive(material)


def read_password(args: argparse.Namespace, *, confirm: bool, prompt: str = "Password: ") -> bytes:
    if args.password_stdin:
        line = sys.stdin.buffer.readline()
        if not line:
            raise SystemExit("No password supplied on stdin")
        return line.rstrip(b"\r\n")

    pw1 = getpass.getpass(prompt).encode("utf-8")
    if not pw1:
        raise SystemExit("Empty passwords are refused. Nice try, entropy gremlin.")
    if confirm:
        pw2 = getpass.getpass("Confirm password: ").encode("utf-8")
        if pw1 != pw2:
            raise SystemExit("Passwords do not match")
    return pw1


def read_key_password(args: argparse.Namespace) -> bytes | None:
    if args.key_password_stdin:
        line = sys.stdin.buffer.readline()
        if not line:
            raise SystemExit("No private-key password supplied on stdin")
        return line.rstrip(b"\r\n")
    return None


def load_public_key_or_cert(path: Path):
    raw = path.read_bytes()
    try:
        cert = x509.load_pem_x509_certificate(raw)
        public_key = cert.public_key()
    except ValueError:
        public_key = serialization.load_pem_public_key(raw)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise SystemExit("Only RSA public keys/certificates are supported for --cert in this version")
    if public_key.key_size < 2048:
        raise SystemExit("RSA public key is too small; use at least 2048 bits")
    return public_key


def load_private_key(path: Path, args: argparse.Namespace):
    raw = path.read_bytes()
    password = read_key_password(args)
    try:
        key = serialization.load_pem_private_key(raw, password=password)
    except TypeError:
        # Encrypted private key and no password supplied.
        password = getpass.getpass("Private key password: ").encode("utf-8")
        key = serialization.load_pem_private_key(raw, password=password)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise SystemExit("Only RSA private keys are supported for --key in this version")
    if key.key_size < 2048:
        raise SystemExit("RSA private key is too small; use at least 2048 bits")
    return key


def rsa_wrap(public_key: rsa.RSAPublicKey, secret: bytes) -> bytes:
    return public_key.encrypt(
        secret,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=b"filecrypt-v2-rsa-oaep",
        ),
    )


def rsa_unwrap(private_key: rsa.RSAPrivateKey, wrapped: bytes) -> bytes:
    return private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=b"filecrypt-v2-rsa-oaep",
        ),
    )


def new_header_and_key(args: argparse.Namespace) -> tuple[dict[str, Any], bytes]:
    use_cert = bool(args.cert)
    use_password = bool(args.password or not use_cert)
    mode = "both" if use_cert and use_password else "cert" if use_cert else "password"

    access: dict[str, Any] = {"mode": mode}
    material = b""

    if use_password:
        n = int(args.scrypt_n)
        if n < 2 or n > MAX_SCRYPT_N or n & (n - 1):
            raise SystemExit(f"--scrypt-n must be a power of 2 between 2 and {MAX_SCRYPT_N}")
        password = read_password(args, confirm=not args.password_stdin)
        params = {
            "salt": b64e(os.urandom(16)),
            "n": n,
            "r": DEFAULT_SCRYPT_R,
            "p": DEFAULT_SCRYPT_P,
        }
        access["scrypt"] = params
        material += scrypt_key(password, params)

    if use_cert:
        public_key = load_public_key_or_cert(Path(args.cert))
        cert_secret = os.urandom(32)
        access["rsa_oaep_sha256"] = {"wrapped_secret": b64e(rsa_wrap(public_key, cert_secret))}
        material += cert_secret

    hkdf_salt = os.urandom(16)
    key = hkdf_key(material, hkdf_salt, mode)
    header = {
        "v": VERSION,
        "alg": "AES-256-GCM",
        "nonce": b64e(os.urandom(12)),
        "hkdf_salt": b64e(hkdf_salt),
        "access": access,
    }
    return header, key


def key_from_header(header: dict[str, Any], args: argparse.Namespace) -> bytes:
    if int(header.get("v", 0)) != VERSION:
        raise ValueError("unsupported filecrypt version")
    if header.get("alg") != "AES-256-GCM":
        raise ValueError("unsupported encryption algorithm")

    access = header.get("access")
    if not isinstance(access, dict):
        raise ValueError("missing access metadata")
    mode = access.get("mode")
    if mode not in {"password", "cert", "both"}:
        raise ValueError("unsupported access mode")

    material = b""
    if mode in {"password", "both"}:
        password = read_password(args, confirm=False)
        material += scrypt_key(password, access["scrypt"])

    if mode in {"cert", "both"}:
        if not args.key:
            raise SystemExit("This file requires an RSA private key: pass --key private_key.pem")
        private_key = load_private_key(Path(args.key), args)
        wrapped = b64d(access["rsa_oaep_sha256"]["wrapped_secret"])
        material += rsa_unwrap(private_key, wrapped)

    return hkdf_key(material, b64d(header["hkdf_salt"]), mode)


def decrypt_container(data: bytes, args: argparse.Namespace) -> tuple[dict[str, Any], bytes, bytes]:
    header, ciphertext, aad = unpack_file(data)
    key = key_from_header(header, args)
    try:
        plaintext = AESGCM(key).decrypt(b64d(header["nonce"]), ciphertext, aad)
    except InvalidTag as exc:
        raise SystemExit("Decryption failed: wrong password/key or corrupted/tampered file") from exc
    return header, plaintext, key


def encrypt_with_header(header: dict[str, Any], key: bytes, plaintext: bytes) -> bytes:
    new_header = copy.deepcopy(header)
    new_header["nonce"] = b64e(os.urandom(12))
    aad = MAGIC + len(json_bytes(new_header)).to_bytes(4, "big") + json_bytes(new_header)
    ciphertext = AESGCM(key).encrypt(b64d(new_header["nonce"]), plaintext, aad)
    return pack_file(new_header, ciphertext)


def encrypt_new(plaintext: bytes, args: argparse.Namespace) -> bytes:
    header, key = new_header_and_key(args)
    return encrypt_with_header(header, key, plaintext)


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        try:
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        finally:
            raise


def choose_editor() -> list[str]:
    configured = os.environ.get("VISUAL") or os.environ.get("EDITOR")
    if configured:
        return shlex.split(configured)
    for candidate in ("vim", "vi"):
        if shutil.which(candidate):
            return [candidate]
    raise SystemExit("No editor found. Set VISUAL or EDITOR, or install vim/vi.")


def edit_bytes(initial: bytes, display_name: str) -> bytes:
    editor = choose_editor()
    base = os.path.basename(editor[0])
    if base in {"vim", "nvim", "vi", "view"} and "-n" not in editor:
        editor = [*editor, "-n"]  # avoid Vim swap files; backups still depend on user config

    old_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="filecrypt-") as tmpdir:
            tmp_path = Path(tmpdir) / display_name
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(str(tmp_path), flags, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(initial)
            result = subprocess.run([*editor, str(tmp_path)])
            if result.returncode != 0:
                raise SystemExit(f"Editor exited with status {result.returncode}; encrypted file was not changed")
            return tmp_path.read_bytes()
    finally:
        os.umask(old_umask)


def output_path_for_plain(path: Path, ext: str) -> Path:
    return path if path.name.endswith(ext) else Path(str(path) + ext)


def run(args: argparse.Namespace) -> int:
    os.umask(0o077)
    path = Path(args.file).expanduser()

    if path.exists() and is_filecrypt(path):
        data = path.read_bytes()
        header, plaintext, key = decrypt_container(data, args)
        if args.decrypt_to_stdout:
            sys.stdout.buffer.write(plaintext)
            return 0
        if args.encrypt_only:
            raise SystemExit("--encrypt-only is for plaintext input, not existing filecrypt files")
        edited = edit_bytes(plaintext, path.stem or "plaintext.txt")
        if edited == plaintext:
            print("No changes; encrypted file left untouched.", file=sys.stderr)
            return 0
        atomic_write(path, encrypt_with_header(header, key, edited))
        print(f"Updated encrypted file: {path}", file=sys.stderr)
        return 0

    if path.exists() and path.name.endswith(args.ext) and not is_filecrypt(path):
        raise SystemExit(
            "This looks like a legacy OpenSSL .enc file, not a filecrypt v2 file. "
            "Decrypt it with the old script/OpenSSL once, then re-encrypt with this version."
        )

    if args.decrypt_to_stdout:
        raise SystemExit("Cannot decrypt: file is missing or is not a filecrypt v2 file")

    if args.encrypt_only:
        if not path.exists():
            raise SystemExit(f"Plaintext input does not exist: {path}")
        plaintext = path.read_bytes()
    else:
        plaintext = path.read_bytes() if path.exists() else b""
        plaintext = edit_bytes(plaintext, path.name or "plaintext.txt")

    out = output_path_for_plain(path, args.ext)
    atomic_write(out, encrypt_new(plaintext, args))
    print(f"Wrote encrypted file: {out}", file=sys.stderr)

    if args.remove_plain and path.exists() and path != out:
        path.unlink()
        print(f"Removed plaintext file: {path}", file=sys.stderr)
    elif path.exists() and path != out and args.encrypt_only:
        print(f"Plaintext kept: {path}  (use --remove-plain to delete it)", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create, open, edit, and resave encrypted files using your editor.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("file", help="encrypted file to edit, or plaintext/new filename to encrypt")
    parser.add_argument("--password", action="store_true", help="require a password for new files; default unless --cert is used")
    parser.add_argument("--cert", help="RSA X.509 certificate or RSA public key PEM for new files")
    parser.add_argument("--key", help="RSA private key PEM for opening cert/both encrypted files")
    parser.add_argument("--password-stdin", action="store_true", help="read file password from stdin; useful for scripts/tests")
    parser.add_argument("--key-password-stdin", action="store_true", help="read encrypted private-key password from stdin")
    parser.add_argument("--scrypt-n", type=int, default=DEFAULT_SCRYPT_N, help="scrypt CPU/memory cost for new password files")
    parser.add_argument("--ext", default=DEFAULT_EXT, help="extension for new encrypted files")
    parser.add_argument("--encrypt-only", action="store_true", help="encrypt existing plaintext without opening the editor")
    parser.add_argument("--decrypt-to-stdout", action="store_true", help="decrypt an existing filecrypt v2 file to stdout")
    parser.add_argument("--remove-plain", action="store_true", help="remove plaintext source after successful encryption")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
