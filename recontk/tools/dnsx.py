"""
recontk.tools.dnsx
~~~~~~~~~~~~~~~~~~~
Dnsx wrapper.

Capabilities : dns.resolve, dns.brute
Output flag  : -json  (per dnsx --help)
Finding types:
  "dns-record"  value = resolved value  metadata = {record_type, host}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class DnsxWrapper(ToolWrapper):
    TOOL_KEY = "dnsx"
    CAPABILITY = "dns.resolve"

    # -silent   : no banner         (per dnsx --help)
    # -resp     : show response     (per dnsx --help)
    # -a -aaaa -cname -mx -ns -txt : record types  (per dnsx --help)
    _DEFAULT_FLAGS: list[str] = [
        "-silent",
        "-resp",
        "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt",
    ]

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        return [
            self._binary,
            "-d", target,
            "-json",                       # JSON output  (per dnsx --help)
            "-o", str(raw_output_path),
            *self._DEFAULT_FLAGS,
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        Dnsx JSON output (per dnsx --help / README):
          {
            "host": "example.com",
            "resolver": [...],
            "a": ["93.184.216.34"],
            "cname": [...],
            "mx": [...],
            "ns": [...],
            "txt": [...],
            "aaaa": [...]
          }
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
            host = obj.get("host", target)
            # Iterate over known record type fields
            for rtype in ("a", "aaaa", "cname", "mx", "ns", "txt"):
                records = obj.get(rtype, [])
                if isinstance(records, str):
                    records = [records]
                for value in records:
                    if not value:
                        continue
                    findings.append(
                        Finding(
                            tool=self.TOOL_KEY,
                            type="dns-record",
                            target=target,
                            value=value,
                            severity=None,
                            metadata={"record_type": rtype.upper(), "host": host},
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_JSONL = """\
{"host":"example.com","a":["93.184.216.34"],"aaaa":[],"cname":[],"mx":["mail.example.com"],"ns":["ns1.example.com","ns2.example.com"],"txt":["v=spf1 include:_spf.example.com ~all"]}
"""


def _test_parse_jsonl(tmp_path: Path) -> None:
    out_file = tmp_path / "dnsx.json"
    out_file.write_text(_SAMPLE_JSONL)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com", "test")
    wrapper = DnsxWrapper(
        binary="/usr/local/bin/dnsx",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "example.com")
    types_seen = {f.metadata["record_type"] for f in findings}
    assert "A" in types_seen
    assert "MX" in types_seen
    assert "NS" in types_seen
    assert "TXT" in types_seen
    a_record = next(f for f in findings if f.metadata["record_type"] == "A")
    assert a_record.value == "93.184.216.34"
    print("dnsx._test_parse_jsonl PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_jsonl(Path(td))
