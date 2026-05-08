"""
recontk.tools.masscan
~~~~~~~~~~~~~~~~~~~~~~
Masscan wrapper.

Capability  : port.scan
Output flag : -oJ <path>   JSON output  (per masscan --help)
Finding types:
  "open-port"  value = "<port>/<proto>"  metadata = {reason, ttl}

Note: masscan requires root/CAP_NET_RAW on most systems.
      The wrapper does not sudo — callers must handle privilege escalation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class MasscanWrapper(ToolWrapper):
    TOOL_KEY = "masscan"
    CAPABILITY = "port.scan"

    # --rate : packets per second (conservative default)  (per masscan --help)
    # --ports: full port range                            (per masscan --help)
    _DEFAULT_FLAGS: list[str] = ["--rate", "1000", "--ports", "1-65535"]

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        return [
            self._binary,
            target,
            "-oJ", str(raw_output_path),   # JSON output  (per masscan --help)
            *self._DEFAULT_FLAGS,
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        Masscan JSON output schema (per masscan --help / README):
          [
            {
              "ip": "10.0.0.1",
              "timestamp": "...",
              "ports": [{"port": 22, "proto": "tcp", "status": "open",
                         "reason": "syn-ack", "ttl": 64}]
            }
          ]
        Masscan wraps the array in a comment-stripped JSON document.
        """
        findings: list[Finding] = []
        text = raw_output_path.read_text(encoding="utf-8").strip()

        # Masscan emits a trailing comma on records which makes it invalid JSON.
        # Strip it: the file is: [\n{...},\n{...},\n]\n
        # We use a line-by-line approach to tolerate this.
        # per masscan source: output/output-json.c
        records: list[dict[str, Any]] = []
        try:
            # First try direct parse (some versions emit valid JSON)
            records = json.loads(text)
        except json.JSONDecodeError:
            # Fall back: strip trailing commas from individual lines
            lines = []
            for line in text.splitlines():
                stripped = line.rstrip()
                if stripped.endswith(","):
                    stripped = stripped[:-1]
                lines.append(stripped)
            clean = "\n".join(lines)
            try:
                records = json.loads(clean)
            except json.JSONDecodeError as exc:
                raise ValueError(f"masscan JSON parse error: {exc}") from exc

        for record in records:
            ip = record.get("ip", target)
            for port_entry in record.get("ports", []):
                port = str(port_entry.get("port", ""))
                proto = port_entry.get("proto", "tcp")
                status = port_entry.get("status", "")
                if status != "open":
                    continue
                reason = port_entry.get("reason", "")
                ttl = port_entry.get("ttl", None)
                findings.append(
                    Finding(
                        tool=self.TOOL_KEY,
                        type="open-port",
                        target=ip,
                        value=f"{port}/{proto}",
                        severity=None,
                        metadata={"reason": reason, "ttl": ttl},
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_JSON = """\
[
{"ip": "10.0.0.1", "timestamp": "1700000000", "ports": [{"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
{"ip": "10.0.0.1", "timestamp": "1700000001", "ports": [{"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
{"ip": "10.0.0.2", "timestamp": "1700000002", "ports": [{"port": 8080, "proto": "tcp", "status": "closed", "reason": "rst", "ttl": 64}]}
]
"""


def _test_parse_json(tmp_path: Path) -> None:
    out_file = tmp_path / "masscan.json"
    out_file.write_text(_SAMPLE_JSON)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "10.0.0.0/24", "test")
    wrapper = MasscanWrapper(
        binary="/usr/bin/masscan",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "10.0.0.0/24")
    # Only open ports
    assert len(findings) == 2, f"Expected 2, got {len(findings)}"
    values = {f.value for f in findings}
    assert "22/tcp" in values
    assert "443/tcp" in values
    assert "8080/tcp" not in values
    print("masscan._test_parse_json PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_json(Path(td))
