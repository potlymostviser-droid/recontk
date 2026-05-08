"""
recontk.tools.theharvester
~~~~~~~~~~~~~~~~~~~~~~~~~~~
theHarvester wrapper.

Capability  : osint.harvest
Output flag : -f <path>  (writes <path>.json and <path>.xml)
              We read the .json file.  (per theHarvester --help)
Finding types:
  "email"      value = email address   metadata = {source}
  "subdomain"  value = hostname        metadata = {ip, source}
  "ip"         value = IP address      metadata = {source}
  "url"        value = URL             metadata = {source}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class TheHarvesterWrapper(ToolWrapper):
    TOOL_KEY = "theHarvester"
    CAPABILITY = "osint.harvest"

    # -b all : use all sources   (per theHarvester --help)
    # -l 500 : result limit      (per theHarvester --help)
    _DEFAULT_FLAGS: list[str] = ["-b", "all", "-l", "500"]

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        # -f writes <path>.json and <path>.xml; we store the stem
        # and read <stem>.json in parse_output
        stem = str(raw_output_path.with_suffix(""))
        return [
            self._binary,
            "-d", target,      # domain  (per theHarvester --help)
            "-f", stem,        # output file stem  (per theHarvester --help)
            *self._DEFAULT_FLAGS,
            *self._extra_args,
        ]

    def _raw_path(self, target: str) -> Path:
        """Override to return the .json path (theHarvester appends .json)."""
        import re
        safe_target = re.sub(r"[^\w.\-]", "_", target)[:64]
        raw_dir = self._workspace.raw_dir(self.TOOL_KEY)
        return raw_dir / f"{safe_target}.json"

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        theHarvester JSON output schema (per theHarvester source/docs):
          {
            "emails": ["user@example.com", ...],
            "hosts": ["sub.example.com:1.2.3.4", ...],
            "ips": ["1.2.3.4", ...],
            "urls": ["https://example.com/path", ...]
          }
        """
        findings: list[Finding] = []
        text = raw_output_path.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"theHarvester JSON parse error: {exc}") from exc

        for email in data.get("emails", []):
            if not email:
                continue
            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type="email",
                    target=target,
                    value=str(email).strip(),
                    severity=None,
                    metadata={"source": "theHarvester"},
                )
            )

        for host_entry in data.get("hosts", []):
            # Entries may be "hostname:ip" or just "hostname"
            if not host_entry:
                continue
            parts = str(host_entry).split(":")
            hostname = parts[0].strip()
            ip = parts[1].strip() if len(parts) > 1 else ""
            if hostname:
                findings.append(
                    Finding(
                        tool=self.TOOL_KEY,
                        type="subdomain",
                        target=target,
                        value=hostname,
                        severity=None,
                        metadata={"ip": ip, "source": "theHarvester"},
                    )
                )

        for ip in data.get("ips", []):
            if not ip:
                continue
            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type="ip",
                    target=target,
                    value=str(ip).strip(),
                    severity=None,
                    metadata={"source": "theHarvester"},
                )
            )

        for url in data.get("urls", []):
            if not url:
                continue
            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type="url",
                    target=target,
                    value=str(url).strip(),
                    severity=None,
                    metadata={"source": "theHarvester"},
                )
            )

        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_JSON = """\
{
  "emails": ["admin@example.com", "security@example.com"],
  "hosts": ["api.example.com:1.2.3.4", "www.example.com"],
  "ips": ["1.2.3.4", "5.6.7.8"],
  "urls": ["https://example.com/login", "https://example.com/admin"]
}
"""


def _test_parse_json(tmp_path: Path) -> None:
    out_file = tmp_path / "theharvester.json"
    out_file.write_text(_SAMPLE_JSON)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com", "test")
    wrapper = TheHarvesterWrapper(
        binary="/usr/bin/theHarvester",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "example.com")
    emails = [f for f in findings if f.type == "email"]
    subdomains = [f for f in findings if f.type == "subdomain"]
    ips = [f for f in findings if f.type == "ip"]
    urls = [f for f in findings if f.type == "url"]
    assert len(emails) == 2
    assert len(subdomains) == 2
    assert len(ips) == 2
    assert len(urls) == 2
    host_with_ip = next(f for f in subdomains if f.value == "api.example.com")
    assert host_with_ip.metadata["ip"] == "1.2.3.4"
    print("theharvester._test_parse_json PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_json(Path(td))
