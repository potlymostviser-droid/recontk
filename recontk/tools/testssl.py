"""
recontk.tools.testssl
~~~~~~~~~~~~~~~~~~~~~~
testssl.sh wrapper.

Capability  : tls.inspect
Output flag : --jsonfile <path>   (per testssl.sh --help)
Finding types:
  "tls-issue"   value = finding id  severity from upstream
                metadata = {ip, port, severity, finding, cve, cwe}
  "tls-info"    value = finding id  severity = "info"
                metadata = same as above
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper

# testssl.sh severity values (per testssl.sh source/docs)
_ISSUE_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_INFO_SEVERITIES  = frozenset({"INFO", "OK", "WARN"})


class TestsslWrapper(ToolWrapper):
    TOOL_KEY = "testssl.sh"
    CAPABILITY = "tls.inspect"

    # --quiet       : no banner              (per testssl.sh --help)
    # --color 0     : no colour codes        (per testssl.sh --help)
    # --warnings off: suppress warnings      (per testssl.sh --help)
    _DEFAULT_FLAGS: list[str] = ["--quiet", "--color", "0", "--warnings", "off"]

    def _output_extension(self) -> str:
        return ".json"

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        return [
            self._binary,
            "--jsonfile", str(raw_output_path),  # (per testssl.sh --help)
            *self._DEFAULT_FLAGS,
            target,
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        testssl.sh JSON output schema (per testssl.sh --help / source):
          [
            {
              "id": "heartbleed",
              "ip": "93.184.216.34/443",
              "port": "443",
              "severity": "CRITICAL",
              "finding": "VULNERABLE",
              "cve": "CVE-2014-0160",
              "cwe": "CWE-126"
            },
            ...
          ]
        """
        findings: list[Finding] = []
        text = raw_output_path.read_text(encoding="utf-8").strip()
        if not text:
            return findings
        try:
            records = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"testssl JSON parse error: {exc}") from exc

        if not isinstance(records, list):
            records = [records]

        for record in records:
            finding_id = record.get("id", "")
            if not finding_id:
                continue
            severity_raw = record.get("severity", "INFO").upper()
            severity_out = severity_raw.lower()  # normalise case

            # Determine finding type
            if severity_raw in _ISSUE_SEVERITIES:
                finding_type = "tls-issue"
            else:
                finding_type = "tls-info"

            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type=finding_type,
                    target=target,
                    value=finding_id,
                    severity=severity_out,   # from upstream
                    metadata={
                        "ip": record.get("ip", ""),
                        "port": record.get("port", ""),
                        "finding": record.get("finding", ""),
                        "cve": record.get("cve", ""),
                        "cwe": record.get("cwe", ""),
                    },
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_JSON = """\
[
  {"id":"heartbleed","ip":"93.184.216.34/443","port":"443","severity":"CRITICAL","finding":"VULNERABLE","cve":"CVE-2014-0160","cwe":"CWE-126"},
  {"id":"SSLv2","ip":"93.184.216.34/443","port":"443","severity":"HIGH","finding":"offered","cve":"","cwe":""},
  {"id":"cert_commonName","ip":"93.184.216.34/443","port":"443","severity":"INFO","finding":"example.com","cve":"","cwe":""}
]
"""


def _test_parse_json(tmp_path: Path) -> None:
    out_file = tmp_path / "testssl.json"
    out_file.write_text(_SAMPLE_JSON)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com:443", "test")
    wrapper = TestsslWrapper(
        binary="/usr/bin/testssl.sh",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "example.com:443")
    issues = [f for f in findings if f.type == "tls-issue"]
    infos = [f for f in findings if f.type == "tls-info"]
    assert len(issues) == 2
    assert len(infos) == 1
    heartbleed = next(f for f in issues if f.value == "heartbleed")
    assert heartbleed.severity == "critical"
    assert heartbleed.metadata["cve"] == "CVE-2014-0160"
    print("testssl._test_parse_json PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_json(Path(td))
