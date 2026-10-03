# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal collection utility; not a public API.

Stable issuer publication identities across CA key rollovers.
"""

from __future__ import annotations

from pathlib import Path

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    IssuerUrls,
    Publication,
)
from ansible_collections.jomrr.ca.plugins.module_utils._crl_models import CrlCredentials
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
    read_json,
    write_json,
)
from ansible_collections.jomrr.ca.plugins.module_utils._paths import (
    archive_directory,
    authority_paths,
    generation_directory,
)
from ansible_collections.jomrr.ca.plugins.module_utils._text import certificate_text
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    load_certificate,
    load_signing_key,
    public_key_bytes,
)

try:
    from ansible_collections.jomrr.ca.plugins.module_utils._types import (
        PrivateKey,
        PublicKey,
    )
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:
    pass


def generation_root(base_dir: str, name: str) -> Path:
    """Return the directory containing public generation records for an authority."""
    return generation_directory(base_dir, safe_path_component(name))


def legacy_id(base_dir: str, name: str, current_id: str, selected: str = "") -> str:
    """Read the pinned identity or recover its owner from pre-upgrade history."""
    root = generation_root(base_dir, name)
    try:
        legacy = str(read_json(str(root / "legacy.json"))["generation_id"])
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
    legacy = legacy_id(base_dir, name, identity, selected)
    return f"{name}-ca" if identity == legacy else f"{name}-ca-{identity}"


def issuer_urls(
    base_dir: str,
    publication: Publication,
    name: str,
    subject: x509.Name,
    public_key: PublicKey,
) -> IssuerUrls:
    """Return AIA/CDP URLs from the actual locked signing identity."""
    stem = generation_stem(base_dir, name, generation_id(subject, public_key))
    return IssuerUrls(
        publication.url(f"{stem}.der", aia=True),
        publication.url(f"{stem}.crl", aia=False),
    )


def retain_generation(
    base_dir: str,
    name: str,
    cert: x509.Certificate,
    attributes: FileAttributes,
    selected: str = "",
) -> bool:
    """Retain public issuer material before replacing a CA and after issuance."""
    identity = generation_id(cert.subject, cert.public_key())
    root = generation_root(base_dir, name)
    legacy = legacy_id(base_dir, name, identity, selected)
    issuers = ca_history(base_dir, name)
    issuers[identity] = cert
    changed = write_json(
        str(root / "legacy.json"),
        {"generation_id": legacy},
        attributes.owner,
        attributes.group,
        "0644",
    )
    attributes = FileAttributes(attributes.owner, attributes.group, "0644")
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
    legacy_id(base_dir, name, generation_id(current.subject, current.public_key()))
    return issuers


def _generation_key_path(base_dir: str, name: str, identity: str) -> str:
    """Select a key via its paired public certificate, current before archive.

    Renewals of the same subject/key may have several serials. Prefer the current
    pair, then archived pairs in serial-directory order. Only a missing key allows
    a later matching pair; unreadable or malformed certificates are errors.
    """
    current = authority_paths(base_dir, name)
    candidates = [Path(current["certificate_pem"])]
    archive = Path(archive_directory(base_dir, name, authority=True))
    candidates.extend(sorted(archive.glob(f"*/{name}-ca.pem")))
    missing: list[str] = []
    for path in candidates:
        try:
            certificate = load_certificate(str(path))
        except FileNotFoundError:
            continue
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Cannot read authority certificate {path}") from exc
        if generation_id(certificate.subject, certificate.public_key()) != identity:
            continue
        key_path = (
            Path(current["private_key"])
            if path == Path(current["certificate_pem"])
            else path.with_suffix(".key")
        )
        try:
            key_path.stat()
        except FileNotFoundError:
            missing.append(str(key_path))
            continue
        return str(key_path)
    if missing:
        raise FileNotFoundError(
            f"Missing signing key for authority {name}, generation {identity}: "
            + ", ".join(missing)
        )
    raise FileNotFoundError(
        f"No certificate/key mapping for authority {name}, generation {identity}; "
        "restore its archived certificate and key pair"
    )


def generation_key(
    base_dir: str,
    name: str,
    identity: str,
    cert: x509.Certificate,
    credentials: CrlCredentials,
) -> PrivateKey:
    """Resolve the public identity first, decrypt exactly one key, then verify it."""
    if generation_id(cert.subject, cert.public_key()) != identity:
        raise ValueError(
            f"Certificate identity mismatch for authority {name}, generation {identity}"
        )
    path = _generation_key_path(base_dir, name, identity)
    try:
        key = load_signing_key(
            path, credentials.archived.get(identity, credentials.current)
        )
    except (ValueError, TypeError) as exc:
        # The backend cannot reliably distinguish bad passwords from corrupt bytes.
        raise ValueError(
            f"Cannot decrypt or parse signing key {path} for generation {identity}; "
            "check its key_passphrase or archived_key_passphrases entry and key file"
        ) from exc
    if public_key_bytes(key) != public_key_bytes(cert.public_key()):
        raise ValueError(
            f"Signing key {path} does not match authority {name}, generation {identity}"
        )
    return key
