# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal collection utility; not a public API.

Stable issuer publication identities across CA key rollovers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    MATERIAL_ERRORS,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    FileAttributes,
    safe_path_component,
    write_file,
)
from ansible_collections.jomrr.ca.plugins.module_utils._generation_history import (
    ca_history,
    generation_id,
    infer_legacy_id,
    issued_history,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_store import (
    _read_json,
    _write_json,
)
from ansible_collections.jomrr.ca.plugins.module_utils._paths import (
    archive_directory,
    authority_paths,
    generation_directory,
)
from ansible_collections.jomrr.ca.plugins.module_utils._text import certificate_text
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    _public_key_bytes,
    load_certificate,
    load_signing_key,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_params import _base_url

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import (
        PrivateKey,
        PublicKey,
    )
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:
    pass


__all__ = [
    "authority_generations",
    "generation_id",
    "generation_key",
    "generation_root",
    "generation_stem",
    "issuer_urls",
    "retain_generation",
]


def generation_root(base_dir: str, name: str) -> Path:
    """Return the directory containing public generation records for an authority."""
    return generation_directory(base_dir, safe_path_component(name))


def _legacy_id(base_dir: str, name: str, current_id: str, selected: str = "") -> str:
    """Read the pinned identity or recover its owner from pre-upgrade history."""
    root = generation_root(base_dir, name)
    try:
        legacy = str(_read_json(str(root / "legacy.json"))["generation_id"])
    except FileNotFoundError:
        try:
            issuers = ca_history(base_dir, name)
        except FileNotFoundError:
            if (
                not Path(authority_paths(base_dir, name)["certificate_pem"]).exists()
                and not list(
                    Path(archive_directory(base_dir, name, authority=True)).glob(
                        f"*/{name}-ca.pem"
                    )
                )
                and not list(root.glob("*/certificate.pem"))
            ):
                return current_id
            raise
        if selected:
            if selected not in issuers:
                raise ValueError(
                    f"Unknown legacy_generation for authority {name}"
                ) from None
            return selected
        return infer_legacy_id(name, issuers, issued_history(base_dir, name, issuers))
    if selected and selected != legacy:
        raise ValueError(f"The legacy URL owner for authority {name} is already pinned")
    return legacy


def generation_stem(base_dir: str, name: str, identity: str, selected: str = "") -> str:
    """Keep the original issuer at its legacy URL and suffix subsequent issuers."""
    legacy = _legacy_id(base_dir, name, identity, selected)
    return f"{name}-ca" if identity == legacy else f"{name}-ca-{identity}"


def issuer_urls(
    params: dict[str, Any], name: str, subject: x509.Name, public_key: PublicKey
) -> None:
    """Set AIA/CDP URLs from the actual locked signing identity."""
    stem = generation_stem(params["base_dir"], name, generation_id(subject, public_key))
    params["aia_url"] = _base_url(params, f"{stem}.der", "aia_base_url")
    params["cdp_url"] = _base_url(params, f"{stem}.crl", "cdp_base_url")


def retain_generation(params: dict[str, Any], cert: x509.Certificate) -> bool:
    """Retain public issuer material before replacing a CA and after issuance."""
    base_dir, name = str(params["base_dir"]), str(params["name"])
    identity = generation_id(cert.subject, cert.public_key())
    root = generation_root(base_dir, name)
    legacy = _legacy_id(
        base_dir, name, identity, str(params.get("legacy_generation") or "")
    )
    issuers = ca_history(base_dir, name)
    issuers[identity] = cert
    changed = _write_json(
        str(root / "legacy.json"),
        {"generation_id": legacy},
        params.get("owner"),
        params.get("group"),
        "0644",
    )
    attributes = FileAttributes(params.get("owner"), params.get("group"), "0644")
    for retained_id, retained in issuers.items():
        for suffix, content in (
            ("pem", retained.public_bytes(serialization.Encoding.PEM)),
            ("der", retained.public_bytes(serialization.Encoding.DER)),
            ("txt", certificate_text(retained)),
        ):
            changed = (
                write_file(
                    str(root / retained_id / f"certificate.{suffix}"),
                    content,
                    attributes,
                )
                or changed
            )
    return changed


def authority_generations(base_dir: str, name: str) -> dict[str, x509.Certificate]:
    """Load retained issuers, or the single legacy issuer before first migration."""
    issuers = ca_history(base_dir, name)
    current = load_certificate(authority_paths(base_dir, name)["certificate_pem"])
    _legacy_id(base_dir, name, generation_id(current.subject, current.public_key()))
    return issuers


def generation_key(
    params: dict[str, Any], identity: str, cert: x509.Certificate
) -> PrivateKey:
    """Find the matching current or archived signing key, never silently omit it."""
    base_dir, name = str(params["base_dir"]), str(params["name"])
    archive = Path(archive_directory(base_dir, name, authority=True))
    paths = [
        Path(authority_paths(base_dir, name)["private_key"]),
        *sorted(archive.glob(f"*/{name}-ca.key")),
    ]
    passphrase = (params.get("archived_key_passphrases") or {}).get(
        identity, params["key_passphrase"]
    )
    if not isinstance(passphrase, str):
        raise TypeError("archived_key_passphrases values must be strings")
    for path in paths:
        try:
            key = load_signing_key(str(path), passphrase)
        except MATERIAL_ERRORS:
            continue
        if _public_key_bytes(key) == _public_key_bytes(cert.public_key()):
            return key
    raise ValueError(
        f"No usable signing key for authority {name}, generation {identity}; "
        "restore its archived key and supply its archived_key_passphrases entry "
        "if the passphrase differs"
    )
