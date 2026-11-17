# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal collection utility; not a public API.

X.509 exports helpers."""

from __future__ import annotations

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_results import (
    ExportChanges,
)
from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    CertificateOperation,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    read_file,
    write_file,
)
from ansible_collections.jomrr.ca.plugins.module_utils._pem_bundle import (
    ensure_key_bundle,
)
from ansible_collections.jomrr.ca.plugins.module_utils._pkcs12_export import (
    ensure_pkcs12_exports,
)
from ansible_collections.jomrr.ca.plugins.module_utils._text import ensure_txt
from ansible_collections.jomrr.ca.plugins.module_utils._x509_chain import (
    intermediate_chain,
    is_self_signed,
    pem_chain,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    load_certificates_bytes,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_state import SignerMaterial

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import (
        PrivateKey,
        PublicKey,
    )
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:
    pass


def ensure_der(params: CertificateOperation, cert: x509.Certificate, path: str) -> bool:
    """Ensure an optional DER-encoded export with its requested file extension."""
    if not path:
        return False
    return write_file(
        path,
        cert.public_bytes(serialization.Encoding.DER),
        params.request["storage"].attributes(),
        check_mode=params.check_mode,
    )


def _read_chain(path: str) -> list[x509.Certificate]:
    """Read intermediate certificates, including legacy root-containing chains."""
    data = read_file(path)
    return intermediate_chain(load_certificates_bytes(data)) if data.strip() else []


def ensure_chain(
    params: CertificateOperation, signer_cert: x509.Certificate | None
) -> bool:
    """Ensure the optional certificate chain copy exists."""
    if not params.paths["chain_src_path"] or not params.paths["chain_path"]:
        return False
    try:
        content = pem_chain(_read_chain(params.paths["chain_src_path"]))
    except FileNotFoundError:
        if signer_cert is None or not is_self_signed(signer_cert):
            raise
        content = b""
    return write_file(
        params.paths["chain_path"],
        content,
        params.request["storage"].attributes(),
        check_mode=params.check_mode,
    )


def chain_content(
    params: CertificateOperation, signer_cert: x509.Certificate | None
) -> bytes:
    """Return the issuing chain content for certificate export bundles."""
    return pem_chain(chain_certificates(params, signer_cert))


def chain_certificates(
    params: CertificateOperation, signer_cert: x509.Certificate | None
) -> list[x509.Certificate]:
    """Return issuing chain certificates for PKCS#12 exports."""
    for path in (params.paths["chain_src_path"], params.paths["chain_path"]):
        if not path:
            continue
        try:
            return _read_chain(path)
        except FileNotFoundError:
            continue
    if signer_cert is None:
        raise ValueError("certificate chain is required for bundle export formats")
    return intermediate_chain([signer_cert])


def _pem_join(*parts: bytes) -> bytes:
    """Join PEM sections with exactly one trailing newline per section."""
    return b"".join(part.rstrip() + b"\n" for part in parts if part)


def ensure_fullchain_bundle(
    params: CertificateOperation, cert: x509.Certificate, bundle_content: bytes
) -> bool:
    """Ensure the requested PEM fullchain bundle exists."""
    if "fullchain" not in params.request["exports"].formats:
        return False
    content = _pem_join(cert.public_bytes(serialization.Encoding.PEM), bundle_content)
    return write_file(
        params.paths["fullchain_path"],
        content,
        params.request["storage"].attributes(),
        check_mode=params.check_mode,
        force=params.request["force"],
    )


def ensure_exports(
    params: CertificateOperation,
    cert: x509.Certificate,
    signer: SignerMaterial,
    key: PrivateKey | PublicKey | None,
    manage_chain: bool,
) -> ExportChanges:
    """Write the requested public and private certificate exports."""
    changes: ExportChanges = {
        "der_changed": ensure_der(params, cert, params.paths["der_path"]),
        "cer_changed": ensure_der(params, cert, params.paths["cer_path"]),
        "txt_changed": ensure_txt(params, cert),
        "chain_changed": ensure_chain(params, signer.cert) if manage_chain else False,
        "pkcs12_changed": False,
        "fullchain_changed": False,
        "bundle_changed": False,
        "pkcs12_paths": {},
        "fritzbox_bundle_changed": False,
    }
    bundle_content = signer.chain_content
    extra_certs = signer.extra_certs
    if not params.request["authority"] and set(
        params.request["exports"].formats
    ).intersection({"pfx", "p12", "fullchain", "bundle", "fritzbox"}):
        bundle_content = bundle_content or chain_content(params, signer.cert)
        if key is not None:
            extra_certs = extra_certs or chain_certificates(params, signer.cert)
    paths: dict[str, str] = {}
    if key is not None:
        changes["pkcs12_changed"], paths = ensure_pkcs12_exports(
            params, key, cert, extra_certs
        )
    changes["fullchain_changed"] = ensure_fullchain_bundle(params, cert, bundle_content)
    if key is not None:
        certificate_chain = _pem_join(
            cert.public_bytes(serialization.Encoding.PEM), bundle_content
        )
        changes["bundle_changed"] = ensure_key_bundle(params, key, certificate_chain)
        changes["fritzbox_bundle_changed"] = ensure_key_bundle(
            params, key, certificate_chain, fritzbox=True
        )
    changes["pkcs12_paths"] = paths
    return changes
