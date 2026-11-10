# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Internal public artifact selection shared by both publication modules."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any, NotRequired, TypedDict

from ansible_collections.jomrr.ca.plugins.module_utils._authority_generations import (
    generation_root,
    generation_stem,
    legacy_id,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    ca_lock_path,
    read_file,
)
from ansible_collections.jomrr.ca.plugins.module_utils._generation_history import (
    ca_history,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_store import read_json
from ansible_collections.jomrr.ca.plugins.module_utils._paths import (
    authority_paths,
    chain_paths,
    crl_paths,
)
from ansible_collections.jomrr.ca.plugins.module_utils._validation import authority_map

AREA_DIRECTORY = {"aia": "aia", "cdp": "crl", "crl": "crl"}


class Artifact(TypedDict):
    """One public source and its publication location."""

    area: str
    src: str
    file: str
    format: NotRequired[str]
    kind: NotRequired[str]


def _base_dir(value: Any) -> str:
    """Return a normalized base directory string."""
    return str(value).rstrip("/")


def _artifact(
    area: str,
    source: str,
    filename: str,
    artifact_format: str,
    kind: str,
) -> Artifact:
    """Return one public artifact descriptor."""
    return {
        "area": area,
        "src": source,
        "file": filename,
        "format": artifact_format,
        "kind": kind,
    }


def _generation_retired(directory: Path) -> bool:
    """Keep a retired generation's final CRL when present, without requiring one."""
    try:
        return bool(read_json(str(directory / "status.json"))["retired"])
    except FileNotFoundError:
        return False


def artifacts_from_authorities(
    authorities: list[dict[str, Any]],
    base_dir: str,
) -> list[Artifact]:
    """Return public AIA/CDP artifacts derived from managed authorities."""
    authority_by_name = authority_map(authorities)
    root = _base_dir(base_dir)
    artifacts: list[Artifact] = []

    for name, authority in authority_by_name.items():
        history = ca_history(root, name)
        history.require_current()
        legacy = legacy_id(root, name, history=history)
        for identity in history.certificates:
            ca_stem = generation_stem(name, identity, legacy)
            retained = generation_root(root, name) / identity
            for artifact_format in ("pem", "der", "txt"):
                source = (
                    str(retained / f"certificate.{artifact_format}")
                    if retained.is_dir()
                    else authority_paths(root, name)[
                        "certificate_text"
                        if artifact_format == "txt"
                        else f"certificate_{artifact_format}"
                    ]
                )
                artifacts.append(
                    _artifact(
                        "aia",
                        source,
                        f"{ca_stem}.{artifact_format}",
                        artifact_format,
                        "certificate",
                    )
                )
            for artifact_format, source in crl_paths(root, ca_stem).items():
                if _generation_retired(retained) and not Path(source).exists():
                    continue
                artifacts.append(
                    _artifact(
                        "cdp",
                        source,
                        Path(source).name,
                        artifact_format,
                        "crl",
                    )
                )

        parent = str(authority.get("parent") or name)
        if parent != name:
            for artifact_format, source in chain_paths(root, name).items():
                artifacts.append(
                    _artifact(
                        "aia",
                        source,
                        Path(source).name,
                        artifact_format,
                        "chain",
                    )
                )

    return artifacts


def resolve_artifacts(params: dict[str, Any]) -> list[Artifact]:
    """Return explicitly supplied or authority-derived public artifacts."""
    artifacts = params.get("artifacts") or []
    if artifacts:
        return [
            Artifact(
                area=str(item.get("area", "")),
                src=str(item.get("src", "")),
                file=str(item.get("file", "")),
            )
            for item in artifacts
        ]
    authorities = params.get("authorities") or []
    if not authorities:
        raise ValueError("artifacts or authorities is required")
    return artifacts_from_authorities(authorities, params["base_dir"])


def artifact_path(area: str, filename: str) -> str:
    """Return a safe relative publication path for one public artifact."""
    directory = AREA_DIRECTORY.get(str(area))
    if directory is None:
        raise ValueError(f"Unsupported publish artifact area: {area}")
    path = PurePosixPath(str(filename))
    if path.name != str(filename) or path.name in ("", ".", ".."):
        raise ValueError(f"Unsafe publish artifact filename: {filename}")
    return str(PurePosixPath(directory) / path.name)


def read_artifacts(artifacts: list[Artifact]) -> dict[str, bytes]:
    """Read public bytes once, rejecting duplicate or unsafe publication paths."""
    contents: dict[str, bytes] = {}
    for artifact in sorted(artifacts, key=lambda item: (item["area"], item["file"])):
        path = artifact_path(artifact["area"], artifact["file"])
        if path in contents:
            raise ValueError(f"Duplicate publish artifact path: {path}")
        contents[path] = read_file(artifact["src"])
    return contents


def publish_lock_paths(params: dict[str, Any]) -> list[str]:
    """Serialize publication with other publishers and authority writers."""
    locks = [ca_lock_path(params["base_dir"], "publish", "archive")]
    if not params["artifacts"]:
        locks.extend(
            ca_lock_path(params["base_dir"], "authority", name)
            for name in authority_map(params["authorities"])
        )
    return locks


def publish_argument_spec(mode: str) -> dict[str, Any]:
    """Return common arguments, keeping each module's file mode default."""
    return {
        "base_dir": {"type": "path", "required": True},
        "dest": {"type": "path", "required": True},
        "artifacts": {"type": "list", "elements": "dict", "default": []},
        "authorities": {
            "type": "list",
            "elements": "dict",
            "default": [],
            "no_log": True,
        },
        "owner": {"type": "str"},
        "group": {"type": "str"},
        "mode": {"type": "str", "default": mode},
        "force": {"type": "bool", "default": False},
    }
