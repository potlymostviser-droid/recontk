"""
recontk.tools.naabu
~~~~~~~~~~~~~~~~~~~~
Naabu wrapper.

Capability  : port.scan
Output flag : -json  (per naabu --help)
Finding types:
  "open-port"  value = "<port>/tcp"  metadata = {host}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class NaabuWrapper(ToolWrapper):
    TOOL_KEY = "naabu"
    CAPABILITY = "port.scan"

    # -silent  : no banner         (per naabu --help)
    # -top-ports 1000 : top ports  (per naabu --help)
    _DEFAULT_FLAGS: list[str] = ["-silent", "-top-ports", "1000"]

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        return [
            self._binary,
            "-host", target,
            "-json",                        # JSON output  (per naabu --help)
            "-o", str(raw_output_path),
            *self._DEFAULT_FLAGS,
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        Naabu JSON output (per naabu --help / README):
          {"ip": "10.0.0.1", "port": 22, "host": "example.com"}
        Newline-delimited.
        """
        findings: list[Finding] = []
        text = raw_output_path.read_text(encoding="utf-8")
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            port = str(obj.get("port", ""))
            ip = obj.get("ip", target)
            if not port:
                continue
            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type="open-port",
                    target=ip,
                    value=f"{port}/tcp",
                    severity=None,
                    metadata={"host": obj.get("host", "")},
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_JSONL = """\
{"ip":"10.0.0.1","port":22,"host":"example.com"}
{"ip":"10.0.0.1","port":443,"host":"example.com"}
{"port":0}
"""


def _test_parse_jsonl(tmp_path: Path) -> None:
    out_file = tmp_path / "naabu.json"
    out_file.write_text(_SAMPLE_JSONL)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com", "test")
    wrapper = NaabuWrapper(
        binary="/usr/local/bin/naabu",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "example.com")
    assert len(findings) == 2, f"Expected 2, got {len(findings)}"
    values = {f.value for f in findings}
    assert "22/tcp" in values
    assert "443/tcp" in values
    print("naabu._test_parse_jsonl PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_jsonl(Path(td))
