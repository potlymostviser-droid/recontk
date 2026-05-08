"""
recontk.tools.ffuf
~~~~~~~~~~~~~~~~~~~
Ffuf wrapper.

Capability  : content.discover
Output flag : -of json -o <path>   (per ffuf --help)
Finding types:
  "content-found"  value = URL  metadata = {status, length, words,
                                             lines, content_type, redirectlocation}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class FfufWrapper(ToolWrapper):
    TOOL_KEY = "ffuf"
    CAPABILITY = "content.discover"

    # Callers MUST pass wordlist via extra_args: ["-w", "/path/to/wordlist"]
    # -silent  : no banner       (per ffuf --help)
    # -mc all  : match all codes (per ffuf --help) — callers filter via -fc
    _DEFAULT_FLAGS: list[str] = ["-silent"]

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        # target is expected to contain FUZZ keyword, e.g.
        # "https://example.com/FUZZ"
        # Callers are responsible for constructing the URL with FUZZ.
        return [
            self._binary,
            "-u", target,
            "-of", "json",                  # output format  (per ffuf --help)
            "-o", str(raw_output_path),
            *self._DEFAULT_FLAGS,
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        Ffuf JSON output schema (per ffuf --help / README):
          {
            "commandline": "...",
            "results": [
              {
                "input": {"FUZZ": "admin"},
                "position": 1,
                "status": 200,
                "length": 1024,
                "words": 100,
                "lines": 50,
                "content-type": "text/html",
                "redirectlocation": "",
                "url": "https://example.com/admin"
              }
            ]
          }
        """
        findings: list[Finding] = []
        text = raw_output_path.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"ffuf JSON parse error: {exc}") from exc

        for result in data.get("results", []):
            url = result.get("url", "")
            if not url:
                continue
            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type="content-found",
                    target=target,
                    value=url,
                    severity=None,
                    metadata={
                        "status": result.get("status"),
                        "length": result.get("length"),
                        "words": result.get("words"),
                        "lines": result.get("lines"),
                        "content_type": result.get("content-type", ""),
                        "redirectlocation": result.get("redirectlocation", ""),
                        "input": result.get("input", {}),
                    },
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_JSON = """\
{
  "commandline": "ffuf -u https://example.com/FUZZ -w wordlist.txt",
  "results": [
    {"url":"https://example.com/admin","status":200,"length":1024,"words":100,"lines":50,"content-type":"text/html","redirectlocation":"","input":{"FUZZ":"admin"}},
    {"url":"https://example.com/login","status":302,"length":0,"words":0,"lines":0,"content-type":"","redirectlocation":"https://example.com/auth","input":{"FUZZ":"login"}}
  ]
}
"""


def _test_parse_json(tmp_path: Path) -> None:
    out_file = tmp_path / "ffuf.json"
    out_file.write_text(_SAMPLE_JSON)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com", "test")
    wrapper = FfufWrapper(
        binary="/usr/local/bin/ffuf",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "https://example.com/FUZZ")
    assert len(findings) == 2
    values = {f.value for f in findings}
    assert "https://example.com/admin" in values
    assert "https://example.com/login" in values
    admin = next(f for f in findings if "admin" in f.value)
    assert admin.metadata["status"] == 200
    print("ffuf._test_parse_json PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_json(Path(td))
