"""
recontk.modules.osint
~~~~~~~~~~~~~~~~~~~~~~
OSINT (Open Source Intelligence) module.

Capabilities used:
  - osint.harvest (theHarvester, gau, waybackurls)

Overlaps with passiverecon; provided as a standalone module for
OSINT-focused scans.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from recontk.core.logging import StructuredLogger
    from recontk.core.runner import Runner

from recontk.models import NormalizedResult


async def run(
    target: str,
    runner: "Runner",
    logger: "StructuredLogger",
    **kwargs: Any,
) -> NormalizedResult:
    """Execute OSINT harvesting against ``target``."""
    log = logger.bind(module="osint", target=target)
    log.event("module_started")

    result = await runner.run_multi("osint.harvest", target, **kwargs)

    urls = [f for f in result.findings if f.type == "url"]
    emails = [f for f in result.findings if f.type == "email"]
    log.event(
        "module_finished",
        url_count=len(urls),
        email_count=len(emails),
        duration_s=round(result.duration_s, 2),
    )
    return result
