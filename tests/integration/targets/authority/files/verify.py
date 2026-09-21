"""Independently inspect installed-module output using cryptography."""

from __future__ import annotations

import json
import sys
import tarfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


def verify_issuance(base: Path) -> None:
    """Verify CA signatures, key protection and revocation state."""
    issuer = x509.load_pem_x509_certificate((base / "ca/issuer-ca.pem").read_bytes())
    web = x509.load_pem_x509_certificate((base / "certs/web/web.pem").read_bytes())
    web.verify_directly_issued_by(issuer)
    assert "changed.example.test" in web.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName)
    chain = x509.load_pem_x509_certificates(
        (base / "chains/issuer-ca-chain.pem").read_bytes()
    )
    assert len(chain) == 2
    chain[0].verify_directly_issued_by(chain[1])
    assert not (base / "chains/root-ca-chain.pem").exists()
    private_path = base / "private/root-ca.key"
    assert private_path.stat().st_mode & 0o777 == 0o600
    serialization.load_pem_private_key(
        private_path.read_bytes(), b"test-root-passphrase"
    )
    crl = x509.load_der_x509_crl((base / "crl/issuer-ca.crl").read_bytes())
    issuer_key = issuer.public_key()
    assert isinstance(issuer_key, ec.EllipticCurvePublicKey)
    assert crl.is_signature_valid(issuer_key)
    assert crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 2
    revoked = crl.get_revoked_certificate_by_serial_number(web.serial_number)
    assert revoked is not None
    assert revoked.extensions.get_extension_for_class(x509.CRLReason).value.reason == (
        x509.ReasonFlags.key_compromise
    )


def verify_profiles(base: Path) -> None:
    """Verify all supported certificate profiles and private exports."""
    issuer = x509.load_pem_x509_certificate((base / "ca/issuer-ca.pem").read_bytes())
    profiles = (
        "tls_server",
        "tls_client",
        "eap_tls_client",
        "identity",
        "identity_full",
        "mskdc",
        "fritzbox",
    )
    for profile in profiles:
        cert = x509.load_pem_x509_certificate(
            (base / f"certs/{profile}/{profile}.pem").read_bytes()
        )
        cert.verify_directly_issued_by(issuer)
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
            profile + ".example.test"
        )
    for profile in ("identity", "identity_full"):
        key, exported_cert, extras = pkcs12.load_key_and_certificates(
            (base / f"certs/{profile}/{profile}.pfx").read_bytes(),
            b"test-export-passphrase",
        )
        assert key is not None and exported_cert is not None and extras
    bundle = (base / "certs/fritzbox/fritzbox-fritzbox.pem").read_bytes()
    serialization.load_pem_private_key(bundle, None)
    assert len(x509.load_pem_x509_certificates(bundle)) == 3


def main() -> None:
    """Validate public artifacts, encrypted keys, inventory and revocation."""
    root = Path(sys.argv[1])
    base = root / "pki"
    verify_issuance(base)
    verify_profiles(base)
    inventory_text = (base / "inventory/ca-inventory.json").read_text()
    assert "test-root-passphrase" not in inventory_text
    assert "test-issuer-passphrase" not in inventory_text
    inventory = json.loads(inventory_text)
    assert inventory["ca_name"] == "test"
    assert len(inventory["authorities"]) == 2
    assert len(inventory["certificates"]) == 8
    assert len(inventory["revocations"]) == 1
    with tarfile.open(root / "public.tar") as archive:
        assert archive.getnames() == ["aia/issuer.der", "crl/issuer.crl"]
        assert all(member.mtime == 0 for member in archive.getmembers())
    print("Verified certificates, chain, profiles, keys, inventory, CRL and archive")


if __name__ == "__main__":
    main()
