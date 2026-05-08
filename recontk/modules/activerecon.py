"""
recontk.modules.activerecon
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Active reconnaissance module.

Capabilities used:
  - dns.resolve

Active: directly queries the target's nameservers.
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
    """Execute active DNS resolution against ``target``."""
    log = logger.bind(module="activerecon", target=target)
    log.event("module_started")

    result = await runner.run("dns.resolve", target)

    log.event(
        "module_finished",
        finding_count=result.finding_count,
        duration_s=round(result.duration_s, 2),
    )
    return result
