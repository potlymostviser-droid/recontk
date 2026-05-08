"""
recontk.tools.httpx_wrap
~~~~~~~~~~~~~~~~~~~~~~~~
httpx (ProjectDiscovery CLI tool) wrapper.
Named httpx_wrap to avoid shadowing the httpx library.

Capability  : http.probe
Output flag : -json  (per httpx --help)
Finding types:
  "http-probe"  value = URL  metadata = {status_code, title, webserver,
                                          content_length, technologies,
                                          cdn, tls, ip}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class HttpxWrapper(ToolWrapper):
    TOOL_KEY = "httpx"
    CAPABILITY = "http.probe"

    # Flags that produce richer JSON output   (per httpx --help)
    _DEFAULT_FLAGS: list[str] = [
        "-silent",          # suppress banner     (per httpx --help)
        "-status-code",     # include status code (per httpx --help)
        "-title",           # include page title  (per httpx --help)
        "-web-server",      # include server hdr  (per httpx --help)
        "-content-length",  # include body length (per httpx --help)
        "-tech-detect",     # technology detect   (per httpx --help)
        "-ip",              # include resolved IP (per httpx --help)
        "-follow-redirects",# follow redirects    (per httpx --help)
        "-threads", "50",   # concurrency         (per httpx --help)
    ]

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        return [
            self._binary,
            "-u", target,                # single target URL/host (per httpx --help)
            "-json",                     # JSON output            (per httpx --help)
            "-o", str(raw_output_path),
            *self._DEFAULT_FLAGS,
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        httpx JSON output is newline-delimited JSON.
        Each object has at minimum: url, status-code
        Full schema documented in httpx README.
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
            url = obj.get("url", "").strip()
            if not url:
                continue

            # Extract fields; keys match httpx JSON output schema
            status_code = obj.get("status-code") or obj.get("status_code")
            title = obj.get("title", "")
            webserver = obj.get("webserver", "") or obj.get("web-server", "")
            content_length = obj.get("content-length") or obj.get("content_length")
            technologies = obj.get("technologies", []) or obj.get("tech", [])
            cdn = obj.get("cdn", False)
            ip = obj.get("host", "") or obj.get("ip", "")
            tls = obj.get("tls", {})

            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type="http-probe",
                    target=target,
                    value=url,
                    severity=None,
                    metadata={
                        "status_code": status_code,
                        "title": title,
                        "webserver": webserver,
                        "content_length": content_length,
                        "technologies": technologies,
                        "cdn": cdn,
                        "ip": ip,
                        "tls": tls,
                    },
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_JSONL = """\
{"url":"https://example.com","status-code":200,"title":"Example","webserver":"nginx/1.24","content-length":1256,"technologies":["Bootstrap"],"host":"93.184.216.34","cdn":false,"tls":{}}
{"url":"https://api.example.com","status-code":401,"title":"","webserver":"","content-length":0,"technologies":[],"host":"93.184.216.35","cdn":false,"tls":{}}
"""


def _test_parse_jsonl(tmp_path: Path) -> None:
    out_file = tmp_path / "httpx.json"
    out_file.write_text(_SAMPLE_JSONL)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com", "test")
    wrapper = HttpxWrapper(
        binary="/usr/local/bin/httpx",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "example.com")
    assert len(findings) == 2
    assert findings[0].value == "https://example.com"
    assert findings[0].metadata["status_code"] == 200
    assert findings[0].metadata["webserver"] == "nginx/1.24"
    assert findings[1].metadata["status_code"] == 401
    print("httpx_wrap._test_parse_jsonl PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_jsonl(Path(td))
