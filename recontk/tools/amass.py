"""
recontk.tools.amass
~~~~~~~~~~~~~~~~~~~~
Amass wrapper (enum subcommand).

Capability  : subdomain.enum
Output flag : -json <path>   (per amass --help)
Finding types:
  "subdomain"  value = FQDN  metadata = {addresses, tag, source, name}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class AmassWrapper(ToolWrapper):
    TOOL_KEY = "amass"
    CAPABILITY = "subdomain.enum"

    # -passive : passive only (no active DNS brute-force)  (per amass --help)
    # -silent  : suppress banner                           (per amass --help)
    _DEFAULT_FLAGS: list[str] = ["-passive", "-silent"]

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        return [
            self._binary,
            "enum",                      # subcommand     (per amass --help)
            "-d", target,
            "-json", str(raw_output_path),
            *self._DEFAULT_FLAGS,
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        Amass JSON output (per amass --help / project wiki):
        Newline-delimited JSON objects:
          {
            "name": "api.example.com",
            "domain": "example.com",
            "addresses": [{"ip": "1.2.3.4", "cidr": "1.2.3.0/24", "asn": 12345}],
            "tag": "cert",
            "source": "CertSpotter"
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
            name = obj.get("name", "").strip()
            if not name:
                continue
            addresses = obj.get("addresses", [])
            tag = obj.get("tag", "")
            source = obj.get("source", "")
            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type="subdomain",
                    target=target,
                    value=name,
                    severity=None,
                    metadata={
                        "addresses": addresses,
                        "tag": tag,
                        "source": source,
                    },
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_JSONL = """\
{"name":"mail.example.com","domain":"example.com","addresses":[{"ip":"1.2.3.4","cidr":"1.2.3.0/24","asn":12345}],"tag":"cert","source":"CertSpotter"}
{"name":"vpn.example.com","domain":"example.com","addresses":[],"tag":"dns","source":"Brute"}
{"name":"","domain":"example.com","addresses":[]}
"""


def _test_parse_jsonl(tmp_path: Path) -> None:
    out_file = tmp_path / "amass.json"
    out_file.write_text(_SAMPLE_JSONL)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com", "test")
    wrapper = AmassWrapper(
        binary="/usr/local/bin/amass",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "example.com")
    assert len(findings) == 2
    values = {f.value for f in findings}
    assert "mail.example.com" in values
    assert "vpn.example.com" in values
    mail = next(f for f in findings if f.value == "mail.example.com")
    assert mail.metadata["source"] == "CertSpotter"
    print("amass._test_parse_jsonl PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_jsonl(Path(td))
