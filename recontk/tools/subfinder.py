"""
recontk.tools.subfinder
~~~~~~~~~~~~~~~~~~~~~~~~
Subfinder wrapper.

Capability  : subdomain.enum
Output flag : -oJ <path>   JSON output  (per subfinder --help)
Finding types:
  "subdomain"  value = FQDN  metadata = {source}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class SubfinderWrapper(ToolWrapper):
    TOOL_KEY = "subfinder"
    CAPABILITY = "subdomain.enum"

    # -silent : no banner/progress       (per subfinder --help)
    # -all    : use all sources          (per subfinder --help)
    _DEFAULT_FLAGS: list[str] = ["-silent", "-all"]

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        return [
            self._binary,
            "-d", target,            # domain flag  (per subfinder --help)
            "-oJ",                   # JSON output  (per subfinder --help)
            "-o", str(raw_output_path),
            *self._DEFAULT_FLAGS,
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        Subfinder JSON output is newline-delimited JSON objects, each like:
          {"host": "sub.example.com", "input": "example.com", "source": ["crtsh"]}
        per subfinder source code / --help
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
            host = obj.get("host", "").strip()
            if not host:
                continue
            sources = obj.get("source", [])
            if isinstance(sources, str):
                sources = [sources]
            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type="subdomain",
                    target=target,
                    value=host,
                    severity=None,
                    metadata={"source": sources},
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_JSONL = """\
{"host": "api.example.com", "input": "example.com", "source": ["crtsh", "hackertarget"]}
{"host": "www.example.com", "input": "example.com", "source": ["dnsdumpster"]}
{"host": "", "input": "example.com", "source": []}
"""


def _test_parse_jsonl(tmp_path: Path) -> None:
    out_file = tmp_path / "subfinder.json"
    out_file.write_text(_SAMPLE_JSONL)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com", "test")
    wrapper = SubfinderWrapper(
        binary="/usr/local/bin/subfinder",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "example.com")
    assert len(findings) == 2, f"Expected 2, got {len(findings)}"
    values = {f.value for f in findings}
    assert "api.example.com" in values
    assert "www.example.com" in values
    assert all(f.type == "subdomain" for f in findings)
    print("subfinder._test_parse_jsonl PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_jsonl(Path(td))
