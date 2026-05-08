"""
recontk.tools.wafw00f
~~~~~~~~~~~~~~~~~~~~~~
Wafw00f wrapper.

Capability  : http.fingerprint
Output flag : -o <path> -f json   (per wafw00f --help)
Finding types:
  "waf-detected"  value = WAF name  metadata = {url, manufacturer}
  "no-waf"        value = "none"    metadata = {url}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class Wafw00fWrapper(ToolWrapper):
    TOOL_KEY = "wafw00f"
    CAPABILITY = "http.fingerprint"

    # -a : find all WAFs, not just the first  (per wafw00f --help)
    _DEFAULT_FLAGS: list[str] = ["-a"]

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        return [
            self._binary,
            target,
            "-o", str(raw_output_path),
            "-f", "json",                  # JSON format  (per wafw00f --help)
            *self._DEFAULT_FLAGS,
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        Wafw00f JSON output schema (per wafw00f --help / source):
          [
            {
              "url": "https://example.com",
              "detected": true,
              "firewall": "Cloudflare",
              "manufacturer": "Cloudflare, Inc."
            }
          ]
        """
        findings: list[Finding] = []
        text = raw_output_path.read_text(encoding="utf-8").strip()
        if not text:
            return findings
        try:
            records = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"wafw00f JSON parse error: {exc}") from exc

        if not isinstance(records, list):
            records = [records]

        for record in records:
            url = record.get("url", target)
            detected = record.get("detected", False)
            firewall = record.get("firewall", "") or ""
            manufacturer = record.get("manufacturer", "") or ""
            if detected and firewall:
                findings.append(
                    Finding(
                        tool=self.TOOL_KEY,
                        type="waf-detected",
                        target=target,
                        value=firewall,
                        severity=None,
                        metadata={"url": url, "manufacturer": manufacturer},
                    )
                )
            else:
                findings.append(
                    Finding(
                        tool=self.TOOL_KEY,
                        type="no-waf",
                        target=target,
                        value="none",
                        severity=None,
                        metadata={"url": url},
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_JSON = """\
[
  {"url":"https://example.com","detected":true,"firewall":"Cloudflare","manufacturer":"Cloudflare, Inc."},
  {"url":"https://api.example.com","detected":false,"firewall":null,"manufacturer":null}
]
"""


def _test_parse_json(tmp_path: Path) -> None:
    out_file = tmp_path / "wafw00f.json"
    out_file.write_text(_SAMPLE_JSON)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com", "test")
    wrapper = Wafw00fWrapper(
        binary="/usr/bin/wafw00f",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "example.com")
    assert len(findings) == 2
    waf = next(f for f in findings if f.type == "waf-detected")
    assert waf.value == "Cloudflare"
    assert waf.metadata["manufacturer"] == "Cloudflare, Inc."
    no_waf = next(f for f in findings if f.type == "no-waf")
    assert no_waf.value == "none"
    print("wafw00f._test_parse_json PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_json(Path(td))
