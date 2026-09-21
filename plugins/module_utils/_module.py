# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Ansible result and error handling for certificate dispatchers."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    OPERATION_ERRORS,
    require_cryptography,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import sanitize_error

if TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule


def execute_certificate(
    module: AnsibleModule,
    operation: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    """Run a certificate operation and serialize its result through Ansible."""
    require_cryptography(module)
    try:
        result = operation(module.params)
    except OPERATION_ERRORS as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))
    module.exit_json(**result)
