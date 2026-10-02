# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Ansible result and error handling for certificate dispatchers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.validation import check_type_dict, check_type_list
from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    OPERATION_ERRORS,
    require_cryptography,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    _secret_values,
    sanitize_error,
)


def _certificate_secrets(params: dict[str, Any]) -> set[str]:
    """Find secrets in the existing free-form dicts, including Ansible string input."""
    secrets = _secret_values(params)
    for name in ("certificate", "certificates", "authorities"):
        value = params.get(name)
        if value is None:
            continue
        try:
            items = (
                [value]
                if name == "certificate"
                else cast(Callable[[Any], list[Any]], check_type_list)(value)
            )
        except TypeError:
            # Let Ansible report malformed arguments, with their raw value hidden.
            secrets.add(str(value))
            continue
        for item in items:
            try:
                mapping = cast(Callable[[Any], dict[str, Any]], check_type_dict)(item)
                secrets.update(_secret_values(mapping))
            except (TypeError, ValueError):
                secrets.add(str(item))
    return secrets - {""}


class CertificateModule(AnsibleModule):
    """Protect nested secrets before Ansible validates, skips or logs the call."""

    def _load_params(self) -> None:
        # Register during loading: doing this after __init__ leaks secrets on
        # argument failures and in Ansible's invocation log. Keep dicts untouched
        # so optional fields, profile defaults and caller metadata remain compatible.
        cast(Callable[[], None], super()._load_params)()
        self.no_log_values.update(_certificate_secrets(self.params))


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
