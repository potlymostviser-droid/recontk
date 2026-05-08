"""
recontk.tools.waybackurls
~~~~~~~~~~~~~~~~~~~~~~~~~~
waybackurls wrapper.

Capability  : osint.harvest
Output      : plain text, one URL per line (no structured output flag)
              # VERIFY: waybackurls has no JSON output flag; plain text only
Finding types:
  "url"  value = URL  metadata = {source: "wayback"}
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class WaybackurlsWrapper(ToolWrapper):
    TOOL_KEY = "waybackurls"
    CAPABILITY = "osint.harvest"

    def _output_extension(self) -> str:
        return ".txt"

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        """
        waybackurls reads from stdin or takes the domain as argument.
        Output is redirected via shell — but we cannot use shell=True.
        Instead we pass the target as argument and capture stdout,
        then write it to raw_output_path ourselves.

        # VERIFY: waybackurls argument vs stdin behaviour
        # per tomnomnom/waybackurls README: accepts domains as arguments
        # or from stdin; we use argument form.
        Output file is written by _exec_and_write() override below.
        """
        return [
            self._binary,
            target,
            # No output file flag — stdout is captured in _exec_and_write
            *self._extra_args,
        ]

    async def run(self, target: str) -> "Any":
        """
        Override run() because waybackurls writes to stdout (not a file).
        We capture stdout and write it to raw_output_path manually.
        """
        import time
        from recontk.models import NormalizedResult

        bound_log = self._log.bind(target=target)
        raw_path = self._raw_path(target)
        cmd = self.build_cmd(target, raw_path)

        bound_log.event("tool_started", cmd=" ".join(cmd), dry_run=self._dry_run)

        if self._dry_run:
            return NormalizedResult(
                tool=self.TOOL_KEY, target=target, duration_s=0.0,
                findings=[], errors=[], raw_path=None,
            )

        if self._rate_limiter is not None:
            await self._rate_limiter.acquire(1)

        start = time.monotonic()
        errors: list[str] = []

        try:
            returncode, stdout, stderr = await self._exec(cmd, target)
        except Exception as exc:
            duration = time.monotonic() - start
            return NormalizedResult(
                tool=self.TOOL_KEY, target=target, duration_s=duration,
                findings=[], errors=[str(exc)], raw_path=None,
            )

        duration = time.monotonic() - start

        # Write captured stdout as the raw file
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(stdout, encoding="utf-8")

        if returncode != 0:
            errors.append(f"Exited with code {returncode}: {stderr[:512]}")

        findings = []
        try:
            findings = self.parse_output(raw_path, target)
        except Exception as exc:
            errors.append(f"Parse error: {exc}")

        bound_log.event(
            "tool_finished",
            returncode=returncode,
            duration_s=round(duration, 2),
            finding_count=len(findings),
        )
        return NormalizedResult(
            tool=self.TOOL_KEY, target=target, duration_s=duration,
            findings=findings, errors=errors,
            raw_path=str(raw_path) if raw_path.exists() else None,
        )

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """Plain text: one URL per line."""
        findings: list[Finding] = []
        text = raw_output_path.read_text(encoding="utf-8")
        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith("http"):
                continue
            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type="url",
                    target=target,
                    value=line,
                    severity=None,
                    metadata={"source": "wayback"},
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_TXT = """\
https://example.com/index.php
https://example.com/wp-login.php
https://example.com/robots.txt
not-a-url
"""


def _test_parse_txt(tmp_path: Path) -> None:
    out_file = tmp_path / "waybackurls.txt"
    out_file.write_text(_SAMPLE_TXT)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com", "test")
    wrapper = WaybackurlsWrapper(
        binary="/usr/local/bin/waybackurls",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "example.com")
    assert len(findings) == 3
    values = {f.value for f in findings}
    assert "https://example.com/wp-login.php" in values
    assert "not-a-url" not in values
    print("waybackurls._test_parse_txt PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_txt(Path(td))
