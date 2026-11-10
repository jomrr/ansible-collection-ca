# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Ansible operation lifecycles for certificate and publication modules."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    OPERATION_ERRORS,
    require_cryptography,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    file_locks,
    sanitize_error,
)
from ansible_collections.jomrr.ca.plugins.module_utils._publish import (
    publish_lock_paths,
)


def execute_certificate(
    module: AnsibleModule,
    operation: Callable[[dict[str, Any]], Mapping[str, object]],
) -> None:
    """Run a certificate operation and serialize its result through Ansible."""
    require_cryptography(module)
    _execute(module, operation)


def execute_publication(
    module: AnsibleModule,
    operation: Callable[[dict[str, Any]], Mapping[str, object]],
) -> None:
    """Run a publication under shared locks with conditional crypto dependency."""

    def publish(params: dict[str, Any]) -> Mapping[str, object]:
        if not params["artifacts"]:
            require_cryptography(module)
        with file_locks(publish_lock_paths(params), readonly=module.check_mode):
            return operation(params)

    _execute(module, publish)


def _execute(
    module: AnsibleModule,
    operation: Callable[[dict[str, Any]], Mapping[str, object]],
) -> None:
    """Serialize results and translate operational errors without exposing secrets."""
    try:
        result = operation(module.params)
    except OPERATION_ERRORS as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))
    module.exit_json(**result)
