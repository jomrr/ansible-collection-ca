# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Typed issuance results and non-secret inventory metadata."""

from __future__ import annotations

from typing import NotRequired, TypedDict

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    CertificateOperation,
    RenewalDecision,
    RenewalPolicy,
)


class CertificateMetadata(TypedDict):
    """Resolved, public certificate information retained by the dispatcher."""

    name: str
    type: str
    common_name: str
    issuer: str
    days: int
    formats: list[str]
    output_dir: str
    renewal: RenewalPolicy
    csr_mode: bool


class MaterialChanges(TypedDict):
    """Changes recorded while managing one key/CSR/certificate generation."""

    directory_changed: bool
    archive_changed: bool
    key_changed: bool
    csr_changed: bool
    cert_changed: bool
    generation_changed: NotRequired[bool]


class ExportChanges(TypedDict):
    """Changes and paths returned by certificate export writers."""

    der_changed: bool
    txt_changed: bool
    chain_changed: bool
    pkcs12_changed: bool
    fullchain_changed: bool
    fritzbox_bundle_changed: bool
    pkcs12_paths: dict[str, str]


class CertificateResult(MaterialChanges, ExportChanges):
    """Serializable result schema; optional fields belong to specific operations."""

    changed: bool
    formats: list[str]
    renewal: RenewalDecision
    csr_path: str
    cert_path: str
    txt_path: str
    fullchain_path: str
    fritzbox_bundle_path: str
    identity_changed: NotRequired[bool]
    material_pending: NotRequired[bool]
    csr_mode: NotRequired[bool]
    common_name: NotRequired[str]
    name: NotRequired[str]
    profile: NotRequired[str]
    inventory_changed: NotRequired[bool]


def certificate_result(
    params: CertificateOperation,
    changes: MaterialChanges,
    exports: ExportChanges,
    renewal: RenewalDecision,
) -> CertificateResult:
    """Combine artifact changes with stable result metadata."""
    result: CertificateResult = {
        "directory_changed": changes["directory_changed"],
        "archive_changed": changes["archive_changed"],
        "key_changed": changes["key_changed"],
        "csr_changed": changes["csr_changed"],
        "cert_changed": changes["cert_changed"],
        "der_changed": exports["der_changed"],
        "txt_changed": exports["txt_changed"],
        "chain_changed": exports["chain_changed"],
        "pkcs12_changed": exports["pkcs12_changed"],
        "fullchain_changed": exports["fullchain_changed"],
        "fritzbox_bundle_changed": exports["fritzbox_bundle_changed"],
        "pkcs12_paths": exports["pkcs12_paths"],
        "changed": any(changes.values())
        or any(value for name, value in exports.items() if name.endswith("_changed")),
        "formats": params.request["exports"].formats,
        "renewal": renewal,
        "csr_path": params.paths["csr_path"],
        "cert_path": params.paths["cert_path"],
        "txt_path": params.paths["txt_path"],
        "fullchain_path": params.paths["fullchain_path"],
        "fritzbox_bundle_path": params.paths["fritzbox_bundle_path"],
    }

    if "generation_changed" in changes:
        result["generation_changed"] = changes["generation_changed"]
    return result
