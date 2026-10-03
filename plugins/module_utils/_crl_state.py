# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal collection utility; not a public API.

Persist CRL sequence numbers independently of the public exports."""

from __future__ import annotations

from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    FileAttributes,
    file_lock,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_store import (
    inventory_lock_path,
    read_json,
    record_path,
    write_json,
)


def _stored_number(path: str) -> int:
    """Read a sequence number, failing on corrupt state instead of resetting it."""
    try:
        record = read_json(path)
    except FileNotFoundError:
        return 0
    number = record["crl_number"]
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise ValueError(f"Invalid CRL number in {path}")
    return number


def last_crl_number(base_dir: str, name: str) -> int:
    """Read the authoritative sequence number independently of CRL exports."""
    with file_lock(inventory_lock_path(base_dir)):
        return _stored_number(record_path(base_dir, "crl_numbers", name))


def store_crl_number(
    base_dir: str, name: str, number: int, attrs: FileAttributes
) -> bool:
    """Reserve the number before exporting its CRL; never move it backwards."""
    with file_lock(inventory_lock_path(base_dir)):
        path = record_path(base_dir, "crl_numbers", name)
        if number < _stored_number(path):
            raise ValueError(f"Refusing to decrease CRL number for {name}")
        return write_json(
            path,
            {"crl_number": number},
            attrs.owner,
            attrs.group,
            "0600",
        )
