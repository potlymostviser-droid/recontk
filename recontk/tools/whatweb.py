"""
recontk.tools.whatweb
~~~~~~~~~~~~~~~~~~~~~~
WhatWeb wrapper.

Capability  : http.fingerprint
Output flag : --log-json=<path>   (per whatweb --help)
Finding types:
  "http-fingerprint"  value = URL  metadata = {plugins, http_status, country}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class WhatWebWrapper(ToolWrapper):
    TOOL_KEY = "whatweb"
    CAPABILITY = "http.fingerprint"

    # -a 3      : aggression level 3 (stealthy)  (per whatweb --help)
    # --quiet   : suppress banner                (per whatweb --help)
    _DEFAULT_FLAGS: list[str] = ["-a", "3", "--quiet"]

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        return [
            self._binary,
            target,
            f"--log-json={raw_output_path}",  # JSON log  (per whatweb --help)
            *self._DEFAULT_FLAGS,
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        WhatWeb JSON output schema (per whatweb --help):
          [
            {
              "target": "https://example.com",
              "http_status": 200,
              "request_config": {...},
              "plugins": {
                "nginx": {"string": ["1.24"]},
                "Bootstrap": {"version": ["4.6"]},
                ...
              }
            }
          ]
        Output may be an array or newline-delimited JSON objects.
        """
        findings: list[Finding] = []
        text = raw_output_path.read_text(encoding="utf-8").strip()
        if not text:
            return findings

        records: list[dict[str, Any]] = []
        # Try array first
        if text.startswith("["):
            try:
                records = json.loads(text)
            except json.JSONDecodeError:
                pass
        if not records:
            # Try newline-delimited
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        for record in records:
            url = record.get("target", target)
            http_status = record.get("http_status", None)
            plugins_raw = record.get("plugins", {})

            # Flatten plugins into a simpler dict
            plugins: dict[str, list[str]] = {}
            for plugin_name, plugin_data in plugins_raw.items():
                if isinstance(plugin_data, dict):
                    # Collect all string/version values
                    values: list[str] = []
                    for key in ("string", "version", "account", "module"):
                        v = plugin_data.get(key, [])
                        if isinstance(v, list):
                            values.extend(str(x) for x in v)
                        elif v:
                            values.append(str(v))
                    plugins[plugin_name] = values
                else:
                    plugins[plugin_name] = []

            country = ""
            country_plugin = plugins_raw.get("Country", {})
            if isinstance(country_plugin, dict):
                country_list = country_plugin.get("string", [])
                if country_list:
                    country = country_list[0]

            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type="http-fingerprint",
                    target=target,
                    value=url,
                    severity=None,
                    metadata={
                        "plugins": plugins,
                        "http_status": http_status,
                        "country": country,
                    },
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_JSON = """\
[{"target":"https://example.com","http_status":200,"plugins":{"nginx":{"string":["1.24"]},"Bootstrap":{"version":["4.6"]},"Country":{"string":["UNITED STATES"],"module":["US"]}}}]
"""


def _test_parse_json(tmp_path: Path) -> None:
    out_file = tmp_path / "whatweb.json"
    out_file.write_text(_SAMPLE_JSON)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com", "test")
    wrapper = WhatWebWrapper(
        binary="/usr/bin/whatweb",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "example.com")
    assert len(findings) == 1
    assert findings[0].metadata["http_status"] == 200
    assert "nginx" in findings[0].metadata["plugins"]
    assert findings[0].metadata["country"] == "UNITED STATES"
    print("whatweb._test_parse_json PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_json(Path(td))
