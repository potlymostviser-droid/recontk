"""
recontk.modules.portdiscovery.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Port scanning + service detection module.

Capabilities used:
  - port.scan
  - service.detect (currently same as port.scan; nmap provides both)

Strategy:
  1. Run port.scan to find open ports.
  2. service.detect is implicit (nmap -sV provides service banners).
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
    ports: list[int] | None = None,
    **kwargs: Any,
) -> NormalizedResult:
    """
    Execute port scanning against ``target``.

    Parameters
    ----------
    ports:
        List of ports to scan.  Passed to the provider (e.g. nmap via extra_args
        or native/portscan via kwargs).
    """
    log = logger.bind(module="portdiscovery", target=target)
    log.event("module_started")

    # If ports are specified and we're using a tool wrapper, format as extra_args
    # For nmap: -p 22,80,443
    # For native: pass ports= kwarg
    extra_args: list[str] | None = None
    if ports:
        port_str = ",".join(str(p) for p in ports)
        extra_args = ["-p", port_str]

    result = await runner.run(
        "port.scan",
        target,
        extra_args=extra_args,
        ports=ports,  # for native backend
        **kwargs,
    )

    open_ports = [f for f in result.findings if f.type == "open-port"]
    log.event(
        "module_finished",
        open_port_count=len(open_ports),
        duration_s=round(result.duration_s, 2),
    )
    return result
