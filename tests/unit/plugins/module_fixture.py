# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Real Ansible argument transport and captured syslog for module tests."""

import io
import json
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stdout
from typing import Any
from unittest.mock import Mock, patch

from ansible.module_utils import basic
from ansible.release import __version__


def module_diagnostics(output: io.StringIO, log: Mock) -> str:
    """Return diagnostics whose secrets must be masked by the module runtime."""
    diagnostics = str(log.call_args_list)
    # Core 2.22+ preserves secrets in the transport for controller-side masking.
    # Integration tests exercise that output; do not simulate masking here.
    if tuple(map(int, __version__.split(".")[:2])) < (2, 22):
        diagnostics += output.getvalue()
    return diagnostics


@contextmanager
def module_transport(inputs: dict[str, Any]) -> Iterator[tuple[io.StringIO, Mock]]:
    """Exercise Ansible's decoder while isolating input transport and syslog."""
    output = io.StringIO()
    with (
        patch.object(
            basic, "_ANSIBLE_ARGS", json.dumps({"ANSIBLE_MODULE_ARGS": inputs}).encode()
        ),
        patch.object(basic, "_PARSED_MODULE_ARGS", None),
        patch.object(basic, "_ANSIBLE_PROFILE", "legacy"),
        patch.object(basic.AnsibleModule, "log") as log,
        redirect_stdout(output),
    ):
        yield output, log
