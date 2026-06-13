#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "filecrypt.py"


def run(cmd, *, input_bytes=b"", cwd=None, env=None):
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    return subprocess.run(
        cmd,
        input=input_bytes,
        cwd=cwd,
        env=full_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        plain = work / "secret.txt"
        plain.write_text("hello secret\n", encoding="utf-8")

        run([sys.executable, str(CLI), "--password-stdin", "--encrypt-only", str(plain)], input_bytes=b"correct horse battery staple\n")
        enc = work / "secret.txt.enc"
        assert enc.exists()

        out = run([sys.executable, str(CLI), "--password-stdin", "--decrypt-to-stdout", str(enc)], input_bytes=b"correct horse battery staple\n")
        assert out.stdout == b"hello secret\n"

        try:
            run([sys.executable, str(CLI), "--password-stdin", "--decrypt-to-stdout", str(enc)], input_bytes=b"wrong\n")
        except subprocess.CalledProcessError:
            pass
        else:
            raise AssertionError("wrong password unexpectedly decrypted")

        print("password smoke test passed")

        # Certificate-only mode
        key = work / "filecrypt.key"
        cert = work / "filecrypt.crt"
        cert_plain = work / "cert-secret.txt"
        cert_plain.write_text("cert secret\n", encoding="utf-8")
        run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-nodes", "-subj", "/CN=filecrypt-test",
        ], cwd=work)
        run([sys.executable, str(CLI), "--cert", str(cert), "--encrypt-only", str(cert_plain)])
        cert_enc = work / "cert-secret.txt.enc"
        out = run([sys.executable, str(CLI), "--key", str(key), "--decrypt-to-stdout", str(cert_enc)])
        assert out.stdout == b"cert secret\n"
        print("certificate smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
