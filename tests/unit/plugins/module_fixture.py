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
