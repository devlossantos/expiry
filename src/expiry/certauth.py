"""Certificate authentication for the Entra app registration (instead of a client secret).

A client secret is a password: whoever has the string can sign in as the app from anywhere. With a
certificate, only the public part is uploaded to Entra and the private key never leaves the server.

The credential file is one PEM file holding the private key and (normally) the certificate, e.g.
created by `expiry entra cert-create`. The thumbprint is calculated from the certificate, so it
does not need to be configured.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_PEM_BLOCK = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----.+?-----END \1-----", re.S)
DEFAULT_PATH = "/data/entra-auth.pem"


class CertError(ValueError):
    pass


@dataclass
class CertCredential:
    private_key_pem: str
    certificate_pem: str | None
    sha1_thumbprint: str
    subject: str = ""
    not_after: datetime | None = None

    def msal_credential(self) -> dict:
        if self.certificate_pem:
            # MSAL >= 1.35 derives the SHA-256 thumbprint (x5t#S256) from the certificate itself
            return {"private_key": self.private_key_pem, "public_certificate": self.certificate_pem}
        return {"private_key": self.private_key_pem, "thumbprint": self.sha1_thumbprint}


def _thumbprint(cert: x509.Certificate) -> str:
    return hashlib.sha1(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()  # noqa: S324 (Entra id)


def load_credential(path: str, configured_thumbprint: str = "") -> CertCredential:
    p = Path(path)
    if not p.is_file():
        raise CertError(f"file not found: {path}")
    text = p.read_text(encoding="utf-8", errors="replace")
    blocks = {m.group(1): m.group(0) for m in _PEM_BLOCK.finditer(text)}
    key_pem = next((b for t, b in blocks.items() if "PRIVATE KEY" in t), None)
    if key_pem is None:
        raise CertError(f"{path} has no private key (expected a PEM with the key and the certificate)")
    if "ENCRYPTED" in key_pem:
        raise CertError(f"{path}: the private key is password-protected; store it unencrypted (chmod 600)")
    try:
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except ValueError as exc:
        raise CertError(f"{path}: cannot read the private key ({exc})") from exc

    cert_pem = blocks.get("CERTIFICATE")
    configured = configured_thumbprint.replace(":", "").replace(" ", "").upper()
    if cert_pem is None:
        if not configured:
            raise CertError(f"{path} has no certificate: add it to the file or set entra.certificate_thumbprint")
        return CertCredential(key_pem, None, configured)

    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise CertError(f"{path}: the private key does not belong to the certificate")
    thumb = _thumbprint(cert)
    if configured and configured != thumb:
        raise CertError(f"entra.certificate_thumbprint {configured} does not match the certificate ({thumb}); "
                        "remove the setting, it is calculated automatically")
    return CertCredential(key_pem, cert_pem, thumb, cert.subject.rfc4514_string(), cert.not_valid_after_utc)


def create(path: str, days: int = 730, common_name: str = "expiry-monitor") -> CertCredential:
    """Create an RSA key + self-signed certificate for Entra app authentication.

    Writes <path> (private key + certificate, mode 600) and <path without .pem>.crt (the public
    certificate to upload to Entra)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(key_pem + cert_pem)
    os.chmod(p, 0o600)
    public_path(path).write_text(cert_pem, encoding="utf-8")
    return load_credential(path)


def public_path(path: str) -> Path:
    p = Path(path)
    return p.with_suffix(".crt") if p.suffix == ".pem" else p.with_name(p.name + ".crt")
