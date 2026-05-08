"""
recontk.tools.gobuster
~~~~~~~~~~~~~~~~~~~~~~~
Gobuster wrapper (dir mode).

Capability  : content.discover
Output flag : -o <path> --no-progress  (gobuster writes plain text;
              JSON output via -q not available in dir mode — use plain)
              # VERIFY: gobuster dir mode JSON output flag if added in v3.6+

Finding types:
  "content-found"  value = URL  metadata = {status, size, redirect}
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class GobusterWrapper(ToolWrapper):
    TOOL_KEY = "gobuster"
    CAPABILITY = "content.discover"

    # Callers MUST pass wordlist via extra_args: ["-w", "/path/to/wordlist"]
    # --no-progress : no progress bar    (per gobuster --help)
    # -q            : quiet mode         (per gobuster --help)
    _DEFAULT_FLAGS: list[str] = ["dir", "--no-progress", "-q"]

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        return [
            self._binary,
            *self._DEFAULT_FLAGS,
            "-u", target,
            "-o", str(raw_output_path),
            *self._extra_args,
        ]

    def _output_extension(self) -> str:
        return ".txt"

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        Gobuster dir plain-text output format (per gobuster --help):
          /admin                (Status: 200) [Size: 1234]
          /login                (Status: 302) [Size: 0] [--> /auth]

        We parse this with a regex since no structured output is available
        in dir mode for gobuster v3.  # VERIFY: gobuster JSON flag in future versions
        """
        findings: list[Finding] = []
        text = raw_output_path.read_text(encoding="utf-8")

        # Pattern: /path (Status: NNN) [Size: NNN] optional [--> redirect]
        pattern = re.compile(
            r"^(?P<path>/[^\s]*)\s+"
            r"\(Status:\s*(?P<status>\d+)\)\s+"
            r"\[Size:\s*(?P<size>\d+)\]"
            r"(?:\s+\[-->\s*(?P<redirect>[^\]]+)\])?",
            re.MULTILINE,
        )

        base = target.rstrip("/")
        for match in pattern.finditer(text):
            path = match.group("path")
            status = int(match.group("status"))
            size = int(match.group("size"))
            redirect = match.group("redirect") or ""
            url = f"{base}{path}"
            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type="content-found",
                    target=target,
                    value=url,
                    severity=None,
                    metadata={
                        "status": status,
                        "size": size,
                        "redirect": redirect,
                    },
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_TXT = """\
/admin                (Status: 200) [Size: 1234]
/login                (Status: 302) [Size: 0] [--> /auth]
/robots.txt           (Status: 200) [Size: 45]
"""


def _test_parse_txt(tmp_path: Path) -> None:
    out_file = tmp_path / "gobuster.txt"
    out_file.write_text(_SAMPLE_TXT)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com", "test")
    wrapper = GobusterWrapper(
        binary="/usr/local/bin/gobuster",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "https://example.com")
    assert len(findings) == 3, f"Expected 3, got {len(findings)}"
    values = {f.value for f in findings}
    assert "https://example.com/admin" in values
    assert "https://example.com/login" in values
    login = next(f for f in findings if "login" in f.value)
    assert login.metadata["redirect"] == "/auth"
    assert login.metadata["status"] == 302
    print("gobuster._test_parse_txt PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_txt(Path(td))
