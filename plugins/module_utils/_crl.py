# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal CRL construction and comparison; not a public API."""

from __future__ import annotations

import datetime as _dt
from typing import Any, cast

from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    MATERIAL_ERRORS,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import read_file
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_summary import (
    _crl_number,
)
from ansible_collections.jomrr.ca.plugins.module_utils._serial import parse_serial
from ansible_collections.jomrr.ca.plugins.module_utils._time import (
    now_utc,
    object_datetime,
    parse_datetime,
    timestamp_iso,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509 import (
    digest_algorithm,
    signature_algorithm,
    subject_from_params,
)

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import (
        PrivateKey,
    )
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    from cryptography.x509.oid import SignatureAlgorithmOID

    REASON_FLAGS = {
        "key_compromise": x509.ReasonFlags.key_compromise,
        "ca_compromise": x509.ReasonFlags.ca_compromise,
        "affiliation_changed": x509.ReasonFlags.affiliation_changed,
        "superseded": x509.ReasonFlags.superseded,
        "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
        "certificate_hold": x509.ReasonFlags.certificate_hold,
        "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
        "aa_compromise": x509.ReasonFlags.aa_compromise,
    }
except ImportError:
    pass


def _load_crl(path: str) -> x509.CertificateRevocationList:
    """Load an existing PEM or DER CRL from disk."""
    data = read_file(path)
    try:
        return x509.load_pem_x509_crl(data)
    except ValueError:
        return x509.load_der_x509_crl(data)


def _parse_revocation_date(value: Any) -> _dt.datetime:
    """Parse a revocation timestamp or return the current UTC time."""
    if not value:
        return now_utc(strip_microseconds=True)
    parsed = parse_datetime(value)
    if parsed is None:
        raise ValueError("revocation date must not be empty")
    return parsed


def _revoked_signature(
    crl: x509.CertificateRevocationList,
) -> list[tuple[int, str, str, str]]:
    """Return comparable revoked certificate entries from an existing CRL."""
    result = []
    for revoked in crl:
        reason = ""
        try:
            reason_ext = revoked.extensions.get_extension_for_class(x509.CRLReason)
            reason = reason_ext.value.reason.name
        except x509.ExtensionNotFound:
            pass
        invalidity_date = ""
        try:
            invalidity_ext = revoked.extensions.get_extension_for_class(
                x509.InvalidityDate
            )
            invalidity_date = timestamp_iso(
                object_datetime(invalidity_ext.value, "invalidity_date")
            )
        except x509.ExtensionNotFound:
            pass
        revocation_date = timestamp_iso(object_datetime(revoked, "revocation_date"))
        result.append((revoked.serial_number, reason, invalidity_date, revocation_date))
    return sorted(result)


def _desired_revoked(entries: list[dict[str, Any]]) -> list[tuple[int, str, str, str]]:
    """Return comparable revoked certificate entries from module params."""
    result = []
    for entry in entries or []:
        serial = parse_serial(entry.get("serial_number", entry.get("serial")))
        reason = str(entry.get("reason") or "")
        invalidity_date = ""
        if entry.get("invalidity_date"):
            invalidity_date = timestamp_iso(
                _parse_revocation_date(entry["invalidity_date"])
            )
        revocation_date = timestamp_iso(
            _parse_revocation_date(entry["revocation_date"])
        )
        result.append((serial, reason, invalidity_date, revocation_date))
    return sorted(result)


def _authority_key_identifier(crl: x509.CertificateRevocationList) -> bytes | None:
    """Return an existing CRL Authority Key Identifier."""
    try:
        return crl.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value.key_identifier
    except x509.ExtensionNotFound:
        return None


def _desired_authority_key_identifier(ca_cert: x509.Certificate) -> bytes:
    """Return the desired CRL Authority Key Identifier."""
    return x509.SubjectKeyIdentifier.from_public_key(ca_cert.public_key()).digest


def _load_existing_crls(
    paths: dict[str, str],
) -> dict[str, x509.CertificateRevocationList | None]:
    """Load existing CRLs for all requested formats."""
    existing: dict[str, x509.CertificateRevocationList | None] = {}
    for crl_format, path in paths.items():
        try:
            existing[crl_format] = _load_crl(path)
        except MATERIAL_ERRORS:
            existing[crl_format] = None
    return existing


def _existing_numbers(
    existing_crls: dict[str, x509.CertificateRevocationList | None],
) -> list[int]:
    """Return all available CRL Number values from existing CRLs."""
    numbers = []
    for crl in existing_crls.values():
        if crl is None:
            continue
        number = _crl_number(crl)
        if number is not None:
            numbers.append(number)
    return numbers


def _same_existing_number(
    existing_crls: dict[str, x509.CertificateRevocationList | None],
) -> bool:
    """Return whether all requested existing CRLs have the same CRL Number."""
    numbers = [
        _crl_number(crl) if crl is not None else None for crl in existing_crls.values()
    ]
    return bool(numbers) and None not in numbers and len(set(numbers)) == 1


def _signature_algorithm_oid(
    ca_cert: x509.Certificate, digest: str
) -> x509.ObjectIdentifier:
    """Derive the CRL signing OID from the CA public key and configured digest."""
    hash_name = digest_algorithm(digest).name.upper()
    public_key = ca_cert.public_key()
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return SignatureAlgorithmOID.ED25519
    if isinstance(public_key, ed448.Ed448PublicKey):
        return SignatureAlgorithmOID.ED448
    for key_class, prefix in (
        (rsa.RSAPublicKey, "RSA"),
        (ec.EllipticCurvePublicKey, "ECDSA"),
        (dsa.DSAPublicKey, "DSA"),
    ):
        if isinstance(public_key, key_class):
            return cast(
                x509.ObjectIdentifier,
                getattr(SignatureAlgorithmOID, f"{prefix}_WITH_{hash_name}"),
            )
    raise ValueError("Unsupported CA public key for CRL signing")


def _needs_rebuild(
    *,
    existing_crls: dict[str, x509.CertificateRevocationList | None],
    params: dict[str, Any],
    desired_signature_algorithm: x509.ObjectIdentifier,
    desired_revoked: list[tuple[int, str, str, str]],
    desired_authority_key: bytes | None,
) -> bool:
    """Return whether existing CRLs differ from desired CRL state."""
    if not _same_existing_number(existing_crls):
        return True
    current_time = now_utc()
    issuer = subject_from_params(params)
    for crl in existing_crls.values():
        if crl is None:
            return True
        if (
            crl.issuer != issuer
            or crl.signature_algorithm_oid != desired_signature_algorithm
        ):
            return True
        if object_datetime(crl, "next_update") <= current_time + _dt.timedelta(
            days=params["renew_before_days"]
        ):
            return True
        if (
            _authority_key_identifier(crl) != desired_authority_key
            or _revoked_signature(crl) != desired_revoked
        ):
            return True
    return False


def _build_crl(
    params: dict[str, Any],
    *,
    crl_number: int,
    ca_cert: x509.Certificate,
    private_key: PrivateKey,
) -> x509.CertificateRevocationList:
    """Build and sign a CRL from module parameters."""
    now = now_utc(strip_microseconds=True)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(subject_from_params(params))
        .last_update(now)
        .next_update(now + _dt.timedelta(days=int(params["next_update_days"])))
        .add_extension(x509.CRLNumber(crl_number), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier(
                _desired_authority_key_identifier(ca_cert), None, None
            ),
            critical=False,
        )
    )
    for entry in params["revoked_certificates"] or []:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(
                parse_serial(entry.get("serial_number", entry.get("serial")))
            )
            .revocation_date(_parse_revocation_date(entry.get("revocation_date")))
        )
        if entry.get("reason"):
            reason = REASON_FLAGS[str(entry["reason"])]
            revoked = revoked.add_extension(x509.CRLReason(reason), critical=False)
        if entry.get("invalidity_date"):
            revoked = revoked.add_extension(
                x509.InvalidityDate(_parse_revocation_date(entry["invalidity_date"])),
                critical=False,
            )
        builder = builder.add_revoked_certificate(revoked.build())
    return builder.sign(
        private_key=private_key,
        algorithm=signature_algorithm(private_key, params["digest"]),
    )
