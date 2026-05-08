"""
Example ToolWrapper implementation for a hypothetical 'mytool' binary.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class MyToolWrapper(ToolWrapper):
    """
    Wrapper for 'mytool' — a hypothetical example.

    TOOL_KEY must match the binary name registered in the capability map
    (or a custom capability added by this plugin).
    """

    TOOL_KEY = "mytool"
    CAPABILITY = "example.scan"

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        return [
            self._binary,
            "--target", target,
            "--output-json", str(raw_output_path),
            "--timeout", str(int(self._timeout_s)),
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        data = json.loads(raw_output_path.read_text(encoding="utf-8"))
        findings: list[Finding] = []
        for item in data.get("results", []):
            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type="example.result",
                    target=target,
                    value=item.get("value", ""),
                    severity=item.get("severity"),  # only if tool provides it
                    metadata=item,
                )
            )
        return findings
