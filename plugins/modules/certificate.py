# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Dispatch one managed CA collection certificate to the built-in X.509 profiles."""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.ca.plugins.module_utils._certificate_engine import (
    ensure_certificate_artifacts,
    single_certificate_argument_spec,
)
from ansible_collections.jomrr.ca.plugins.module_utils._module import (
    execute_certificate,
)


def run_module() -> None:
    """Run the Ansible module for dispatched certificate profiles."""
    module = cast(Callable[..., AnsibleModule], AnsibleModule)(
        argument_spec=single_certificate_argument_spec(),
        supports_check_mode=False,
    )

    execute_certificate(module, ensure_certificate_artifacts)


def main() -> None:
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
