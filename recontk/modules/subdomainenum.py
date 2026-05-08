"""
recontk.modules.subdomainenum
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Subdomain enumeration module.

Capabilities used:
  - subdomain.enum (multi-provider: subfinder, amass, native)

Strategy: run all available providers and merge findings.
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
    """Execute multi-provider subdomain enumeration against ``target``."""
    log = logger.bind(module="subdomainenum", target=target)
    log.event("module_started")

    result = await runner.run_multi("subdomain.enum", target, **kwargs)

    log.event(
        "module_finished",
        subdomain_count=result.finding_count,
        duration_s=round(result.duration_s, 2),
    )
    return result
