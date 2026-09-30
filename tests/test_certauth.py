import os
import sys

import pytest

from expiry.certauth import CertError, create, load_credential, public_path
from expiry.config import validate

from conftest import make_config


def test_create_and_load(tmp_path):
    path = str(tmp_path / "entra-auth.pem")
    cred = create(path, days=30, common_name="expiry-test")
    assert public_path(path).read_text().startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE KEY" not in public_path(path).read_text()
    if sys.platform != "win32":
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    again = load_credential(path)
    assert again.sha1_thumbprint == cred.sha1_thumbprint and len(cred.sha1_thumbprint) == 40
    assert "CN=expiry-test" in again.subject
    msal = again.msal_credential()
    assert set(msal) == {"private_key", "public_certificate"}  # MSAL derives the SHA-256 thumbprint


def test_thumbprint_checks(tmp_path):
    path = str(tmp_path / "a.pem")
    cred = create(path)
    colons = ":".join(cred.sha1_thumbprint[i:i + 2] for i in range(0, 40, 2)).lower()
    assert load_credential(path, colons).sha1_thumbprint == cred.sha1_thumbprint  # format-tolerant
    with pytest.raises(CertError, match="does not match"):
        load_credential(path, "00" * 20)


def test_key_only_file_needs_thumbprint(tmp_path):
    path = tmp_path / "a.pem"
    create(str(path))
    key_only = tmp_path / "key.pem"
    key_only.write_text(path.read_text().split("-----BEGIN CERTIFICATE-----")[0])
    with pytest.raises(CertError, match="no certificate"):
        load_credential(str(key_only))
    cred = load_credential(str(key_only), "AB" * 20)
    assert cred.msal_credential() == {"private_key": cred.private_key_pem, "thumbprint": "AB" * 20}


def test_mismatched_key_and_cert(tmp_path):
    a, b = tmp_path / "a.pem", tmp_path / "b.pem"
    create(str(a))
    create(str(b))
    key_a = a.read_text().split("-----BEGIN CERTIFICATE-----")[0]
    cert_b = "-----BEGIN CERTIFICATE-----" + b.read_text().split("-----BEGIN CERTIFICATE-----")[1]
    mixed = tmp_path / "mixed.pem"
    mixed.write_text(key_a + cert_b)
    with pytest.raises(CertError, match="does not belong"):
        load_credential(str(mixed))


def test_config_validation_uses_certificate(tmp_path):
    path = str(tmp_path / "a.pem")
    create(path)
    base = dict(email__enabled=False, sources__entra__enabled=True, entra__tenant_id="t", entra__client_id="c")
    errors, _ = validate(make_config(entra__certificate_path=path, **base))
    assert not [e for e in errors if e.startswith("entra")]  # no thumbprint needed
    errors, _ = validate(make_config(entra__certificate_path=str(tmp_path / "missing.pem"), **base))
    assert any("file not found" in e for e in errors)
