"""
recontk.tools.nuclei
~~~~~~~~~~~~~~~~~~~~~
Nuclei wrapper.

Capability  : vuln.scan
Output flag : -jsonl  (per nuclei --help)
Finding types:
  "vuln"  value = template-id  metadata = {name, severity, matched_at,
                                            tags, description, reference,
                                            curl_command}
Severity    : taken directly from nuclei JSON field "severity"
              valid upstream values: info, low, medium, high, critical
              (per nuclei template schema)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class NucleiWrapper(ToolWrapper):
    TOOL_KEY = "nuclei"
    CAPABILITY = "vuln.scan"

    # -silent   : no banner            (per nuclei --help)
    # -nc       : no colour            (per nuclei --help)
    # -stats    : show progress stats  (per nuclei --help) — goes to stderr, safe
    _DEFAULT_FLAGS: list[str] = ["-silent", "-nc"]

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        return [
            self._binary,
            "-u", target,                    # target URL/host   (per nuclei --help)
            "-jsonl",                        # JSONL output      (per nuclei --help)
            "-o", str(raw_output_path),
            *self._DEFAULT_FLAGS,
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        Nuclei JSONL output schema (per nuclei --help / project README):
          {
            "template-id": str,
            "info": {"name": str, "severity": str, "tags": [...],
                     "description": str, "reference": [...]},
            "matched-at": str,
            "curl-command": str   (optional)
          }
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

            template_id = obj.get("template-id", "")
            info = obj.get("info", {})
            severity = info.get("severity", None)
            name = info.get("name", "")
            tags = info.get("tags", [])
            description = info.get("description", "")
            reference = info.get("reference", [])
            matched_at = obj.get("matched-at", "")
            curl_command = obj.get("curl-command", "")

            if not template_id:
                continue

            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type="vuln",
                    target=target,
                    value=template_id,
                    severity=severity,  # directly from upstream
                    metadata={
                        "name": name,
                        "matched_at": matched_at,
                        "tags": tags,
                        "description": description,
                        "reference": reference,
                        "curl_command": curl_command,
                    },
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_JSONL = """\
{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell","severity":"critical","tags":["cve","rce"],"description":"Log4j RCE","reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]},"matched-at":"https://example.com/login","curl-command":"curl -X GET ..."}
{"template-id":"tech-detect-nginx","info":{"name":"Nginx Detection","severity":"info","tags":["tech"],"description":"Detects nginx","reference":[]},"matched-at":"https://example.com","curl-command":""}
{"template-id":"","info":{},"matched-at":""}
"""


def _test_parse_jsonl(tmp_path: Path) -> None:
    out_file = tmp_path / "nuclei.jsonl"
    out_file.write_text(_SAMPLE_JSONL)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com", "test")
    wrapper = NucleiWrapper(
        binary="/usr/local/bin/nuclei",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "example.com")

    # Empty template-id record is skipped
    assert len(findings) == 2, f"Expected 2, got {len(findings)}"
    cve = next(f for f in findings if f.value == "CVE-2021-44228")
    assert cve.severity == "critical"
    assert cve.metadata["matched_at"] == "https://example.com/login"
    assert "rce" in cve.metadata["tags"]

    tech = next(f for f in findings if f.value == "tech-detect-nginx")
    assert tech.severity == "info"
    print("nuclei._test_parse_jsonl PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_jsonl(Path(td))
