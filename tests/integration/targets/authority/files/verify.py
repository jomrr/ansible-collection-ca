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
    for relative in ("ca/root-ca", "ca/issuer-ca", "certs/web/web"):
        der = (base / f"{relative}.der").read_bytes()
        assert (base / f"{relative}.cer").read_bytes() == der
        assert x509.load_der_x509_certificate(der) == x509.load_pem_x509_certificate(
            (base / f"{relative}.pem").read_bytes()
        )
    assert "changed.example.test" in web.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName)
    chain = x509.load_pem_x509_certificates(
        (base / "chains/issuer-ca-chain.pem").read_bytes()
    )
    assert chain == [issuer]
    root = x509.load_pem_x509_certificate((base / "ca/root-ca.pem").read_bytes())
    issuer.verify_directly_issued_by(root)
    for suffix in ("der", "txt"):
        assert (base / f"chains/issuer-ca-chain.{suffix}").read_bytes() == (
            base / f"ca/issuer-ca.{suffix}"
        ).read_bytes()
    assert x509.load_pem_x509_certificates(
        (base / "certs/web/web-chain.pem").read_bytes()
    ) == [issuer]
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
    assert crl.issuer == issuer.subject
    pem_crl = x509.load_pem_x509_crl((base / "crl/issuer-ca.crl.pem").read_bytes())
    assert pem_crl.public_bytes(serialization.Encoding.DER) == crl.public_bytes(
        serialization.Encoding.DER
    )
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
        if profile == "mskdc":
            assert x509.ObjectIdentifier("1.3.6.1.4.1.311.25.1") not in {
                extension.oid for extension in cert.extensions
            }
            assert any(
                isinstance(name, x509.OtherName)
                and name.type_id == x509.ObjectIdentifier("1.3.6.1.5.2.2")
                for name in cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value
            )
            cert.extensions.get_extension_for_oid(
                x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2")
            )
    for profile in ("identity", "identity_full"):
        key, exported_cert, extras = pkcs12.load_key_and_certificates(
            (base / f"certs/{profile}/{profile}.pfx").read_bytes(),
            b"test-export-passphrase",
        )
        assert key is not None and exported_cert is not None
        assert extras == [issuer]
    verify_pem_bundles(base, issuer)


def verify_pem_bundles(base: Path, issuer: x509.Certificate) -> None:
    """Compare generic exports and the unchanged FRITZ!Box byte layout."""
    bundle = (base / "certs/fritzbox/fritzbox-fritzbox.pem").read_bytes()
    serialization.load_pem_private_key(bundle, None)
    cert = x509.load_pem_x509_certificate(
        (base / "certs/fritzbox/fritzbox.pem").read_bytes()
    )
    assert x509.load_pem_x509_certificates(bundle) == [cert, issuer]
    assert bundle == (
        (base / "certs/fritzbox/fritzbox.pem").read_bytes()
        + issuer.public_bytes(serialization.Encoding.PEM)
        + (base / "certs/fritzbox/fritzbox.key").read_bytes()
    )
    for name, password, header in (
        ("web", None, b"EC PRIVATE KEY"),
        ("fritzbox", None, b"RSA PRIVATE KEY"),
    ):
        directory = base / "certs" / name
        path = directory / f"{name}-bundle.pem"
        content = path.read_bytes()
        assert path.stat().st_mode & 0o777 == 0o600
        assert b"-----BEGIN " + header + b"-----" in content
        key = serialization.load_pem_private_key(content, password)
        certificate = x509.load_pem_x509_certificate(
            (directory / f"{name}.pem").read_bytes()
        )
        assert x509.load_pem_x509_certificates(content) == [certificate, issuer]
        assert key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) == certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )


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
    assert inventory["base_url"] == "http://pki.example.test"
    assert len(inventory["authorities"]) == 2
    assert len(inventory["certificates"]) == 8
    assert len(inventory["revocations"]) == 1
    with tarfile.open(root / "public.tar") as archive:
        assert archive.getnames() == [
            "aia/issuer-ca-chain.der",
            "aia/issuer-ca-chain.pem",
            "aia/issuer-ca-chain.txt",
            "aia/issuer.cer",
            "aia/issuer.der",
            "aia/root-ca.pem",
            "crl/issuer.crl",
        ]
        member = archive.extractfile("aia/issuer.cer")
        assert member is not None
        expected_der = (base / "ca/issuer-ca.der").read_bytes()
        assert member.read() == expected_der
        assert (root / "webroot/aia/issuer.cer").read_bytes() == expected_der
        for suffix in ("pem", "der", "txt"):
            filename = f"aia/issuer-ca-chain.{suffix}"
            member = archive.extractfile(filename)
            assert member is not None
            expected = (base / f"chains/issuer-ca-chain.{suffix}").read_bytes()
            assert member.read() == expected
            assert (root / "webroot" / filename).read_bytes() == expected
        assert (root / "webroot/aia/root-ca.pem").read_bytes() == (
            base / "ca/root-ca.pem"
        ).read_bytes()
        assert all(member.mtime == 0 for member in archive.getmembers())
    print("Verified certificates, chain, profiles, keys, inventory, CRL and archive")


if __name__ == "__main__":
    main()
