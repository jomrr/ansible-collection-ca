# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal collection utility; not a public API.

Recover issuer identities and their remaining certificate lifetimes from history.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    MATERIAL_ERRORS,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    file_lock,
    safe_path_component,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_lookup import (
    record_certificates,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_store import (
    _inventory_lock_path,
    _read_collection,
)
from ansible_collections.jomrr.ca.plugins.module_utils._paths import (
    archive_directory,
    authority_paths,
    generation_directory,
)
from ansible_collections.jomrr.ca.plugins.module_utils._serial import normalize_hex
from ansible_collections.jomrr.ca.plugins.module_utils._time import (
    certificate_not_valid_after,
    certificate_not_valid_before,
    parse_datetime,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    _public_key_bytes,
    load_certificate,
)

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import PublicKey
    from cryptography import x509
except ImportError:
    pass


def generation_id(subject: x509.Name, public_key: PublicKey) -> str:
    """Identify an issuer by its complete subject and public key, across renewals."""
    return hashlib.sha256(
        subject.public_bytes() + _public_key_bytes(public_key)
    ).hexdigest()


def ca_history(base_dir: str, name: str) -> dict[str, x509.Certificate]:
    """Recover every CA identity from current, archived and retained certificates."""
    name = safe_path_component(name)
    paths = [
        *sorted(
            Path(archive_directory(base_dir, name, authority=True)).glob(
                f"*/{name}-ca.pem"
            )
        ),
        *sorted(generation_directory(base_dir, name).glob("*/certificate.pem")),
    ]
    result: dict[str, x509.Certificate] = {}
    for path in paths:
        cert = load_certificate(str(path))
        identity = generation_id(cert.subject, cert.public_key())
        if identity not in result or certificate_not_valid_after(
            cert
        ) > certificate_not_valid_after(result[identity]):
            result[identity] = cert
    current = load_certificate(authority_paths(base_dir, name)["certificate_pem"])
    result[generation_id(current.subject, current.public_key())] = current
    return result


def _record_certificate(
    base_dir: str, record: dict[str, Any]
) -> x509.Certificate | None:
    """Find a historical certificate without following a mutable current pointer."""
    name = safe_path_component(str(record["name"]))
    serial = safe_path_component(str(record["certificate"]["serial_number_hex"]))
    record = {
        **record,
        "name": name,
        "certificate": {**record["certificate"], "serial_number_hex": serial},
    }
    filename = (
        f"{name}-ca.pem" if record["record_type"] == "authority" else f"{name}.pem"
    )
    for cert in record_certificates(
        base_dir, record, archive_first=True, archive_filename=filename
    ):
        if cert.serial_number == int(serial, 16):
            return cert
    return None


def _record_issuer(
    base_dir: str, record: dict[str, Any], issuers: dict[str, x509.Certificate]
) -> str | None:
    """Resolve inventory AKI metadata or verify archived material against each key."""
    summary = record["certificate"]
    identifier = summary.get("extensions", {}).get("authority_key_identifier", "")
    if identifier:
        matches = [
            identity
            for identity, issuer in issuers.items()
            if summary["issuer"] == issuer.subject.rfc4514_string()
            and normalize_hex(identifier)
            == x509.SubjectKeyIdentifier.from_public_key(issuer.public_key())
            .digest.hex()
            .upper()
        ]
        if len(matches) == 1:
            return matches[0]
    cert = _record_certificate(base_dir, record)
    if cert is not None:
        for identity, issuer in issuers.items():
            try:
                cert.verify_directly_issued_by(issuer)
            except MATERIAL_ERRORS:
                continue
            return identity
    return None


def issued_history(
    base_dir: str, name: str, issuers: dict[str, x509.Certificate]
) -> list[dict[str, Any]]:
    """Read leaf, external-CA and managed subordinate-CA issuance history."""
    with file_lock(_inventory_lock_path(base_dir)):
        records = [
            record
            for record in _read_collection(base_dir, "issued_certificates")
            if record["issuer"] == name
        ]
        records.extend(
            record
            for record in _read_collection(base_dir, "authority_certificates")
            if record["parent"] == name and not record["self_signed"]
        )
        return [
            {**record, "issuer_generation": _record_issuer(base_dir, record, issuers)}
            for record in records
        ]


def legacy_references(name: str, record: dict[str, Any]) -> bool:
    """Return whether an issued certificate embeds an unsuffixed issuer URL."""
    extensions = record["certificate"].get("extensions", {})
    locations = [
        entry["location"]
        for entry in extensions.get("authority_information_access", [])
    ]
    locations.extend(
        value
        for point in extensions.get("crl_distribution_points", [])
        for value in point
    )
    return any(
        Path(urlsplit(location.removeprefix("URI:")).path).name
        in {f"{name}-ca.der", f"{name}-ca.crl"}
        for location in locations
    )


def infer_legacy_id(
    name: str, issuers: dict[str, x509.Certificate], records: list[dict[str, Any]]
) -> str:
    """Adopt a provable legacy owner; ask for explicit selection on URL conflicts."""
    owners = {
        record["issuer_generation"]
        for record in records
        if legacy_references(name, record)
    }
    unknown = None in owners
    owners.discard(None)
    if len(owners) == 1 and not unknown:
        return str(next(iter(owners)))
    if not owners and not unknown:
        oldest = min(certificate_not_valid_before(cert) for cert in issuers.values())
        candidates = [
            identity
            for identity, cert in issuers.items()
            if certificate_not_valid_before(cert) == oldest
        ]
        if len(candidates) == 1:
            return candidates[0]
    choices = ", ".join(
        f"{identity} (serial {cert.serial_number:X})"
        for identity, cert in issuers.items()
    )
    raise ValueError(
        f"Select legacy_generation in crl for authority {name}: multiple archived "
        "issuers can own its shared legacy AIA/CDP URLs. "
        f"Available generations: {choices}"
    )


def retirement_times(
    issuers: dict[str, x509.Certificate], records: list[dict[str, Any]]
) -> dict[str, datetime]:
    """Bound retirement by issued and CA expiry; retain on uncertainty."""
    result = {}
    for identity, issuer in issuers.items():
        ca_expiry = certificate_not_valid_after(issuer)
        relevant = [
            record for record in records if record["issuer_generation"] == identity
        ]
        uncertain = any(
            record["issuer_generation"] is None
            and record["certificate"]["issuer"] == issuer.subject.rfc4514_string()
            for record in records
        )
        expiries = [
            parse_datetime(record["certificate"]["not_valid_after"])
            for record in relevant
        ]
        known = [expiry for expiry in expiries if expiry is not None]
        result[identity] = (
            min(ca_expiry, max(known)) if known and not uncertain else ca_expiry
        )
    return result
