"""
recontk.modules.vulnchecks
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Vulnerability scanning module.

Capabilities used:
  - vuln.scan (nuclei)

Requires nuclei to be installed.  No native fallback exists.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from recontk.core.logging import StructuredLogger
    from recontk.core.runner import Runner

from recontk.core.errors import CapabilityUnavailableError
from recontk.models import NormalizedResult


async def run(
    target: str,
    runner: "Runner",
    logger: "StructuredLogger",
    **kwargs: Any,
) -> NormalizedResult:
    """Execute vulnerability scanning against ``target``."""
    log = logger.bind(module="vulnchecks", target=target)
    log.event("module_started")

    try:
        result = await runner.run("vuln.scan", target, **kwargs)
    except CapabilityUnavailableError:
        log.warning("Nuclei not available; skipping vuln checks")
        return NormalizedResult(
            tool="vulnchecks-module",
            target=target,
            duration_s=0.0,
            findings=[],
            errors=["vuln.scan capability unavailable (nuclei not installed)"],
        )

    vulns = [f for f in result.findings if f.type == "vuln"]
    log.event(
        "module_finished",
        vuln_count=len(vulns),
        duration_s=round(result.duration_s, 2),
    )
    return result
