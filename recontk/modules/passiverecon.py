"""
recontk.modules.passiverecon
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Passive reconnaissance module.

Capabilities used:
  - whois
  - osint.harvest (theHarvester, gau, waybackurls)

No active probing; safe for pre-engagement reconnaissance.
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
    """
    Execute passive reconnaissance against ``target``.

    Steps:
      1. WHOIS lookup
      2. OSINT harvesting (all available providers)

    Returns
    -------
    NormalizedResult
        Merged results from all passive capabilities.
    """
    log = logger.bind(module="passiverecon", target=target)
    log.event("module_started")

    merged = NormalizedResult(
        tool="passiverecon-module",
        target=target,
        duration_s=0.0,
        findings=[],
        errors=[],
    )

    # WHOIS
    try:
        whois_result = await runner.run("whois", target)
        merged.merge(whois_result)
    except Exception as exc:  # noqa: BLE001
        log.warning("WHOIS failed", error=str(exc))
        merged.errors.append(f"whois: {exc}")

    # OSINT harvesting (multi-provider)
    try:
        osint_result = await runner.run_multi("osint.harvest", target)
        merged.merge(osint_result)
    except Exception as exc:  # noqa: BLE001
        log.warning("OSINT harvest failed", error=str(exc))
        merged.errors.append(f"osint.harvest: {exc}")

    log.event(
        "module_finished",
        finding_count=merged.finding_count,
        duration_s=round(merged.duration_s, 2),
    )
    return merged
