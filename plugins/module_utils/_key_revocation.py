# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Internal checks against public keys of locally recorded compromised certificates."""

from __future__ import annotations

from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._file import file_lock
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_lookup import (
    certificate_issuer,
    record_certificates,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_store import (
    _inventory_lock_path,
    _read_collection,
)
from ansible_collections.jomrr.ca.plugins.module_utils._serial import normalize_hex
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    _cert_fingerprint,
    _public_key_fingerprint,
)

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import (
        PublicKey,
    )
except ImportError:
    pass


COMPROMISE_REASONS = {"key_compromise", "ca_compromise"}


def _record_key_fingerprint(base_dir: str, record: dict[str, Any]) -> str:
    """Resolve older inventory records from their current or archived certificate."""
    certificate = record["certificate"]
    if certificate.get("public_key_sha256"):
        return str(certificate["public_key_sha256"])
    for cert in record_certificates(base_dir, record):
        if normalize_hex(_cert_fingerprint(cert).hex()) == normalize_hex(
            certificate["fingerprints"]["sha256"]
        ):
            return _public_key_fingerprint(cert.public_key())
    raise ValueError(
        f"Cannot identify the compromised public key of {record['name']}: "
        "restore its recorded certificate or generation archive before issuance"
    )


def validate_key_revocation(params: dict[str, Any], key: PublicKey) -> None:
    """Reject reuse of a known compromised key, regardless of name or current serial."""
    base_dir = str(params["base_dir"])
    fingerprint = _public_key_fingerprint(key)
    with file_lock(_inventory_lock_path(base_dir)):
        compromised = {
            (event["issuer"], event["serial_number_hex"])
            for event in _read_collection(base_dir, "revocations")
            if event.get("reason") in COMPROMISE_REASONS
        }
        if not compromised:
            return
        records = _read_collection(base_dir, "issued_certificates")
        records.extend(_read_collection(base_dir, "authority_certificates"))
        for record in records:
            issuer = certificate_issuer(record)
            serial = record["certificate"]["serial_number_hex"]
            if (issuer, serial) not in compromised:
                continue
            if fingerprint == _record_key_fingerprint(base_dir, record):
                raise ValueError(
                    f"Certificate {params['name']} uses a public key recorded as "
                    "compromised. Generate a new key: use renewal.rekey for due "
                    "renewals or force for managed keys; external CSRs must use "
                    "a new key. Renaming the certificate does not clear the revocation."
                )
