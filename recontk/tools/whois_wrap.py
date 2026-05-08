"""
recontk.tools.whois_wrap
~~~~~~~~~~~~~~~~~~~~~~~~
whois CLI wrapper.

Capability  : whois
Output      : plain text (whois has no JSON output flag)
              # VERIFY: no structured output flag exists for the system whois binary
Finding types:
  "whois-record"  value = registrar  metadata = {raw, registrant, dates, nameservers}
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class WhoisWrapper(ToolWrapper):
    TOOL_KEY = "whois"
    CAPABILITY = "whois"

    def _output_extension(self) -> str:
        return ".txt"

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        # whois writes to stdout; we capture it in the overridden run()
        return [
            self._binary,
            target,
            *self._extra_args,
        ]

    async def run(self, target: str) -> "Any":
        """
        Override run() because whois writes to stdout (not a file).
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
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(stdout, encoding="utf-8")

        if returncode != 0:
            errors.append(f"Exited with code {returncode}: {stderr[:512]}")

        findings = []
        try:
            findings = self.parse_output(raw_path, target)
        except Exception as exc:
            errors.append(f"Parse error: {exc}")

        return NormalizedResult(
            tool=self.TOOL_KEY, target=target, duration_s=duration,
            findings=findings, errors=errors,
            raw_path=str(raw_path) if raw_path.exists() else None,
        )

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        Parse key WHOIS fields from plain-text output via regex.
        We extract: Registrar, Registrant, dates, name servers.
        Raw text is always preserved in metadata.
        """
        text = raw_output_path.read_text(encoding="utf-8")

        def _extract(pattern: str) -> str:
            m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            return m.group(1).strip() if m else ""

        def _extract_all(pattern: str) -> list[str]:
            return [m.strip() for m in re.findall(pattern, text, re.IGNORECASE)]

        registrar = _extract(r"^Registrar:\s*(.+)$")
        registrant = _extract(r"^Registrant(?:\s+Organization)?:\s*(.+)$")
        created = _extract(r"Creation Date:\s*(.+)$")
        expires = _extract(r"(?:Expiry|Expiration) Date:\s*(.+)$")
        updated = _extract(r"Updated Date:\s*(.+)$")
        nameservers = _extract_all(r"^Name Server:\s*(.+)$")

        if not registrar and not registrant:
            # Could not extract any meaningful fields; store raw only
            return [
                Finding(
                    tool=self.TOOL_KEY,
                    type="whois-record",
                    target=target,
                    value="unparsed",
                    severity=None,
                    metadata={"raw": text[:4096]},
                )
            ]

        return [
            Finding(
                tool=self.TOOL_KEY,
                type="whois-record",
                target=target,
                value=registrar or "unknown",
                severity=None,
                metadata={
                    "registrar": registrar,
                    "registrant": registrant,
                    "created": created,
                    "expires": expires,
                    "updated": updated,
                    "nameservers": nameservers,
                    "raw": text[:4096],
                },
            )
        ]


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_TXT = """\
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar: ICANN
Updated Date: 2023-08-14T07:01:31Z
Creation Date: 1995-08-14T04:00:00Z
Expiry Date: 2024-08-13T04:00:00Z
Registrant Organization: Internet Assigned Numbers Authority
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
"""


def _test_parse_txt(tmp_path: Path) -> None:
    out_file = tmp_path / "whois.txt"
    out_file.write_text(_SAMPLE_TXT)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com", "test")
    wrapper = WhoisWrapper(
        binary="/usr/bin/whois",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "example.com")
    assert len(findings) == 1
    f = findings[0]
    assert f.value == "ICANN"
    assert f.metadata["registrant"] == "Internet Assigned Numbers Authority"
    assert len(f.metadata["nameservers"]) == 2
    assert f.metadata["created"] == "1995-08-14T04:00:00Z"
    print("whois_wrap._test_parse_txt PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_txt(Path(td))
