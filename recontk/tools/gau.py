"""
recontk.tools.gau
~~~~~~~~~~~~~~~~~~
gau (GetAllUrls) wrapper.

Capability  : osint.harvest
Output flag : --json  (per gau --help)
Finding types:
  "url"  value = URL  metadata = {source}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class GauWrapper(ToolWrapper):
    TOOL_KEY = "gau"
    CAPABILITY = "osint.harvest"

    # --threads 5  : concurrency      (per gau --help)
    # --subs       : include subdomains (per gau --help)
    _DEFAULT_FLAGS: list[str] = ["--threads", "5", "--subs"]

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        return [
            self._binary,
            target,
            "--json",                       # JSON output  (per gau --help)
            "--output", str(raw_output_path),
            *self._DEFAULT_FLAGS,
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        gau JSON output is newline-delimited JSON objects:
          {"url": "https://example.com/path", "metadata": {"source": "wayback"}}
        per gau --help / README
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
                # gau sometimes emits plain URLs without JSON wrapper
                # when --json is not fully honoured in older versions
                # VERIFY: gau --json output format consistency across versions
                if line.startswith("http"):
                    findings.append(
                        Finding(
                            tool=self.TOOL_KEY,
                            type="url",
                            target=target,
                            value=line,
                            severity=None,
                            metadata={"source": "gau"},
                        )
                    )
                continue
            url = obj.get("url", "").strip()
            if not url:
                continue
            meta = obj.get("metadata", {}) or {}
            source = meta.get("source", "gau") if isinstance(meta, dict) else "gau"
            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type="url",
                    target=target,
                    value=url,
                    severity=None,
                    metadata={"source": source},
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_JSONL = """\
{"url":"https://example.com/login","metadata":{"source":"wayback"}}
{"url":"https://example.com/admin","metadata":{"source":"commoncrawl"}}
{"url":""}
"""


def _test_parse_jsonl(tmp_path: Path) -> None:
    out_file = tmp_path / "gau.json"
    out_file.write_text(_SAMPLE_JSONL)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com", "test")
    wrapper = GauWrapper(
        binary="/usr/local/bin/gau",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "example.com")
    assert len(findings) == 2
    values = {f.value for f in findings}
    assert "https://example.com/login" in values
    assert "https://example.com/admin" in values
    sources = {f.metadata["source"] for f in findings}
    assert "wayback" in sources
    print("gau._test_parse_jsonl PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_jsonl(Path(td))
