"""
recontk.modules.webinspect
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Web application inspection module.

Capabilities used:
  - http.probe
  - http.fingerprint
  - screenshot
  - tls.inspect

Strategy:
  1. Probe HTTP/HTTPS to confirm the target is a web server.
  2. Fingerprint technologies.
  3. Capture screenshot.
  4. If HTTPS, inspect TLS configuration.
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
    """Execute web inspection against ``target``."""
    log = logger.bind(module="webinspect", target=target)
    log.event("module_started")

    merged = NormalizedResult(
        tool="webinspect-module",
        target=target,
        duration_s=0.0,
        findings=[],
        errors=[],
    )

    # HTTP probe
    try:
        probe_result = await runner.run("http.probe", target, **kwargs)
        merged.merge(probe_result)
    except Exception as exc:  # noqa: BLE001
        log.warning("HTTP probe failed", error=str(exc))
        merged.errors.append(f"http.probe: {exc}")

    # HTTP fingerprinting
    try:
        fp_result = await runner.run("http.fingerprint", target, **kwargs)
        merged.merge(fp_result)
    except Exception as exc:  # noqa: BLE001
        log.warning("HTTP fingerprint failed", error=str(exc))
        merged.errors.append(f"http.fingerprint: {exc}")

    # Screenshot
    try:
        screenshot_result = await runner.run("screenshot", target, **kwargs)
        merged.merge(screenshot_result)
    except Exception as exc:  # noqa: BLE001
        log.warning("Screenshot failed", error=str(exc))
        merged.errors.append(f"screenshot: {exc}")

    # TLS inspection (if target uses https or has :443 in it)
    if "https" in target.lower() or ":443" in target:
        try:
            tls_result = await runner.run("tls.inspect", target, **kwargs)
            merged.merge(tls_result)
        except Exception as exc:  # noqa: BLE001
            log.warning("TLS inspect failed", error=str(exc))
            merged.errors.append(f"tls.inspect: {exc}")

    log.event(
        "module_finished",
        finding_count=merged.finding_count,
        duration_s=round(merged.duration_s, 2),
    )
    return merged
