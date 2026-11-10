# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal collection utility; not a public API.

X.509 material helpers."""

from __future__ import annotations

import datetime as _dt
from pathlib import Path
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    CertificateOperation,
    RenewalDecision,
)
from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    MATERIAL_ERRORS,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    FileAttributes,
    read_file,
    set_attrs,
    write_file,
)
from ansible_collections.jomrr.ca.plugins.module_utils._key_revocation import (
    validate_key_revocation,
)
from ansible_collections.jomrr.ca.plugins.module_utils._paths import archive_directory
from ansible_collections.jomrr.ca.plugins.module_utils._serial import serial_hex
from ansible_collections.jomrr.ca.plugins.module_utils._time import (
    now_utc,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_compare import (
    certificate_needs_replacement,
    csr_needs_replacement,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_extensions import (
    add_extensions,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    as_public_key,
    csr_common_name,
    generate_private_key,
    key_matches,
    key_spec,
    load_certificate,
    load_csr,
    load_csr_bytes,
    load_private_key,
    private_key_pem,
    signature_algorithm,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_state import (
    CertificateSpec,
    SignerMaterial,
)

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import PrivateKey
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:
    pass


def ensure_directory(path: str | None, owner: Any, group: Any, mode: Any) -> bool:
    """Create a directory and enforce requested attributes."""
    if not path:
        return False
    Path(path).mkdir(parents=True, exist_ok=True)
    return set_attrs(path, owner, group, mode)


def _archive_dir(params: CertificateOperation, cert: x509.Certificate) -> str:
    """Return the archive directory for one existing certificate generation."""
    return archive_directory(
        str(params.request["storage"].base_dir),
        str(params.request["name"]),
        authority=bool(params.request["authority"]),
        serial=serial_hex(cert.serial_number),
    )


def _archive_path(
    params: CertificateOperation, cert: x509.Certificate, source_path: str
) -> str:
    """Return the archive path for an existing managed source path."""
    return f"{_archive_dir(params, cert)}/{Path(source_path).name}"


def _archive_file(
    params: CertificateOperation,
    cert: x509.Certificate | None,
    source_path: str,
    mode: str,
) -> bool:
    """Copy a current managed file into its generation archive if present."""
    if cert is None or not source_path:
        return False
    try:
        content = read_file(source_path)
    except FileNotFoundError:
        return False
    return write_file(
        _archive_path(params, cert, source_path),
        content,
        FileAttributes(
            params.request["storage"].owner,
            params.request["storage"].group,
            mode,
        ),
        check_mode=params.check_mode,
    )


def archive_existing_material(
    params: CertificateOperation,
    cert: x509.Certificate | None,
    *,
    include_private_key: bool,
) -> bool:
    """Archive the current generation before replacing it."""
    if cert is None:
        return False
    changed = False
    public_paths = (
        params.paths["cert_path"],
        params.paths["csr_path"],
        params.paths["der_path"],
        params.paths["txt_path"],
        params.paths["chain_path"],
    )
    for path in public_paths:
        changed = (
            _archive_file(params, cert, path, params.request["storage"].public_mode)
            or changed
        )
    if include_private_key:
        changed = (
            _archive_file(
                params,
                cert,
                params.paths["key_path"],
                params.request["storage"].key_mode,
            )
            or changed
        )
    return changed


def reusable_key(params: CertificateOperation, *, rekey: bool) -> PrivateKey | None:
    """Validate a reusable key without generating or modifying any material."""
    spec = key_spec(params.request["key"].key_type, params.request["key"].key_size)
    if params.request["force"] or rekey:
        return None
    try:
        key = load_private_key(
            params.paths["key_path"], params.request["key"].passphrase
        )
    except FileNotFoundError:
        return None
    if not key_matches(key, spec):
        return None
    validate_key_revocation(params, key.public_key())
    return key


def ensure_key(
    params: CertificateOperation, *, rekey: bool, existing_cert: x509.Certificate | None
) -> tuple[PrivateKey, bool]:
    """Ensure the private key exists with the requested key properties."""
    spec = key_spec(params.request["key"].key_type, params.request["key"].key_size)
    key = reusable_key(params, rekey=rekey)
    changed = False
    if key is None:
        _archive_file(
            params,
            existing_cert,
            params.paths["key_path"],
            params.request["storage"].key_mode,
        )
        key = generate_private_key(spec)
        changed = True
        content = private_key_pem(key, params.request["key"].passphrase)
        changed = (
            write_file(
                params.paths["key_path"],
                content,
                params.request["storage"].attributes(private=True),
            )
            or changed
        )
    else:
        changed = (
            set_attrs(
                params.paths["key_path"],
                params.request["storage"].owner,
                params.request["storage"].group,
                params.request["storage"].key_mode,
            )
            or changed
        )
    if not key_matches(key, spec):
        raise ValueError("Private key does not match the requested specification")
    return key, changed


def ensure_csr(
    params: CertificateOperation,
    key: PrivateKey,
    subject: x509.Name,
    csr_extensions: list[tuple[x509.ObjectIdentifier, bool, x509.ExtensionType]],
) -> tuple[x509.CertificateSigningRequest, bool]:
    """Ensure the CSR matches the requested subject, key, and extensions."""
    try:
        existing = load_csr(params.paths["csr_path"])
    except MATERIAL_ERRORS:
        existing = None
    changed = csr_needs_replacement(
        params, existing, CertificateSpec(key, subject, csr_extensions)
    )
    if changed:
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        builder = add_extensions(builder, csr_extensions)
        csr = builder.sign(key, signature_algorithm(key, params.request["digest"]))
    else:
        if existing is None:
            raise ValueError("Missing CSR after comparison")
        csr = existing
    content = (
        csr.public_bytes(serialization.Encoding.PEM)
        if changed
        else read_file(params.paths["csr_path"])
    )
    changed = (
        write_file(
            params.paths["csr_path"],
            content,
            params.request["storage"].attributes(),
        )
        or changed
    )
    return csr, changed


def _external_csr_bytes(params: CertificateOperation) -> bytes:
    """Return CSR bytes from inline content or a source path."""
    csr_content = params.request["csr"].content
    if csr_content:
        return str(csr_content).encode()
    csr_source_path = str(params.request["csr"].path or "")
    if csr_source_path:
        return read_file(csr_source_path)
    raise ValueError("csr_path or csr_content is required for CSR signing")


def validated_external_csr(
    params: CertificateOperation,
) -> x509.CertificateSigningRequest:
    """Read and validate the request before creating any managed material."""
    csr = load_csr_bytes(_external_csr_bytes(params))
    if not csr.is_signature_valid:
        raise ValueError("CSR signature verification failed")

    common_name = str(params.request["subject"].common_name or "").strip()
    requested_cn = csr_common_name(csr)
    if common_name and common_name != requested_cn:
        raise ValueError(
            f"CSR common name {requested_cn!r} does not match {common_name!r}"
        )

    validate_key_revocation(params, csr.public_key())
    return csr


def ensure_external_csr(
    params: CertificateOperation, csr: x509.CertificateSigningRequest
) -> tuple[x509.CertificateSigningRequest, bool]:
    """Copy a validated external CSR into the managed CSR path."""
    content = csr.public_bytes(serialization.Encoding.PEM)
    changed = write_file(
        params.paths["csr_path"],
        content,
        params.request["storage"].attributes(),
        force=params.request["force"],
        check_mode=params.check_mode,
    )
    return csr, changed


def ensure_certificate(
    params: CertificateOperation,
    spec: CertificateSpec,
    signer: SignerMaterial,
    renewal: RenewalDecision,
    existing_cert: x509.Certificate | None,
) -> tuple[x509.Certificate, bool]:
    """Ensure the certificate matches the requested issuer and profile."""
    if signer.key is None:
        raise ValueError("Certificate signing requires a private key")
    issuer = signer.cert.subject if signer.cert is not None else spec.subject
    now = now_utc(strip_microseconds=True)
    builder = (
        x509.CertificateBuilder()
        .subject_name(spec.subject)
        .issuer_name(issuer)
        .public_key(as_public_key(spec.key))
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=1))
        .not_valid_after(now + _dt.timedelta(days=int(params.request["days"])))
    )
    builder = add_extensions(builder, spec.extensions)
    existing = existing_cert
    if existing is None:
        try:
            existing = load_certificate(params.paths["cert_path"])
        except MATERIAL_ERRORS:
            existing = None
    changed = certificate_needs_replacement(params, existing, spec, signer, renewal)

    if changed:
        archive_existing_material(
            params,
            existing_cert,
            include_private_key=False,
        )
        cert = builder.sign(
            private_key=signer.key,
            algorithm=signature_algorithm(signer.key, params.request["digest"]),
        )
        content = cert.public_bytes(serialization.Encoding.PEM)
    else:
        content = read_file(params.paths["cert_path"])
        cert = load_certificate(params.paths["cert_path"])

    changed = (
        write_file(
            params.paths["cert_path"],
            content,
            params.request["storage"].attributes(),
        )
        or changed
    )
    return cert, changed
