# SPDX-License-Identifier: Elastic-2.0
"""Generate a throwaway self-signed cert for integration tests (skips if no openssl)."""
import os
import shutil
import subprocess
import tempfile

_cached = None


def ensure_dev_cert():
    global _cached
    if _cached is not None:
        return _cached
    if shutil.which("openssl") is None:
        return None
    d = tempfile.mkdtemp(prefix="glyph-cert-")
    cert = os.path.join(d, "cert.pem")
    key = os.path.join(d, "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    _cached = (cert, key)
    return _cached
