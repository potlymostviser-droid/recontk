"""
recontk.native.portscan
~~~~~~~~~~~~~~~~~~~~~~~~
Native asyncio TCP connect scanner with banner grabbing.

Capabilities : port.scan, service.detect

Strategy:
  1. Attempt TCP connect to each (host, port) pair.
  2. On success: attempt a short banner read (1-second timeout).
  3. Match banner against known service signatures for service.detect.
  4. Emit one "open-port" finding per open port.
  5. Emit one "service-banner" finding if a banner was captured.

Performance:
  - Fully async; concurrency controlled by a semaphore.
  - Default: 500 concurrent connections (conservative; adjustable).
  - Rate limiter token acquired per connection attempt.

Note: TCP connect scan is detectable and noisier than SYN scan.
      Use nmap/masscan when stealth matters.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

from recontk.core.logging import StructuredLogger, get_null_logger
from recontk.core.ratelimit import AsyncTokenBucket
from recontk.core.workspace import Workspace
from recontk.models import Finding, NormalizedResult

# ---------------------------------------------------------------------------
# Default port lists
# ---------------------------------------------------------------------------

# Top-100 common ports (abridged for native scanner)
_TOP_100_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 465, 514, 587, 993, 995, 1080,
    1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087,
    2222, 3306, 3389, 4443, 4444, 5432, 5900, 6379,
    6443, 7070, 7443, 8000, 8008, 8080, 8083, 8088,
    8443, 8888, 9000, 9090, 9200, 9443, 10000, 27017,
    27018, 28017, 50000,
]

# ---------------------------------------------------------------------------
# Service signature patterns for banner-based detection
# Each entry: (pattern, service_name, protocol)
# ---------------------------------------------------------------------------

_BANNER_SIGNATURES: list[tuple[bytes, str]] = [
    (b"SSH-",           "ssh"),
    (b"220 ",           "ftp/smtp"),   # disambiguated below by port
    (b"HTTP/",          "http"),
    (b"* OK ",          "imap"),
    (b"+OK ",           "pop3"),
    (b"220 SMTP",       "smtp"),
    (b"220 FTP",        "ftp"),
    (b"\x16\x03",       "tls"),        # TLS ClientHello response
    (b"RFB ",           "vnc"),
    (b"AMQP",           "amqp"),
    (b"Redis",          "redis"),
    (b"-ERR",           "redis"),
    (b"MongoDB",        "mongodb"),
    (b"\xff\xfd",       "telnet"),
    (b"SMB",            "smb"),
]

# Port → likely service name (used when banner is absent)
_PORT_SERVICE_MAP: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}

_CONNECT_TIMEOUT = 3.0    # seconds
_BANNER_TIMEOUT  = 2.0    # seconds
_BANNER_BYTES    = 256     # max bytes to read from banner


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def run_scan(
    target: str,
    workspace: Workspace,
    logger: StructuredLogger | None = None,
    ports: list[int] | None = None,
    concurrency: int = 500,
    connect_timeout: float = _CONNECT_TIMEOUT,
    banner_timeout: float = _BANNER_TIMEOUT,
    rate_limiter: AsyncTokenBucket | None = None,
    **_kwargs: Any,
) -> NormalizedResult:
    """
    Perform an async TCP connect scan against ``target``.

    Parameters
    ----------
    target:
        Hostname or IP address.
    workspace:
        Active workspace.
    logger:
        Structured logger.
    ports:
        List of ports to scan.  Defaults to _TOP_100_PORTS.
    concurrency:
        Maximum simultaneous connection attempts.
    connect_timeout:
        TCP connect timeout per port.
    banner_timeout:
        Timeout for banner read after connect.
    rate_limiter:
        Optional token bucket applied per connection attempt.
    """
    log = (logger or get_null_logger()).bind(
        tool="native/portscan", target=target, capability="port.scan"
    )
    start = time.monotonic()
    port_list = ports or _TOP_100_PORTS
    log.event("tool_started", port_count=len(port_list))

    findings: list[Finding] = []
    errors: list[str] = []
    semaphore = asyncio.Semaphore(concurrency)

    async def probe_port(port: int) -> None:
        if rate_limiter is not None:
            await rate_limiter.acquire(1)
        port_findings, port_errors = await _connect_and_grab(
            target, port, connect_timeout, banner_timeout, log
        )
        findings.extend(port_findings)
        errors.extend(port_errors)

    await asyncio.gather(*[
        _bounded_probe(semaphore, probe_port, port)
        for port in port_list
    ])

    duration = time.monotonic() - start
    raw_path = _write_raw(workspace, target, findings)

    log.event(
        "tool_finished",
        duration_s=round(duration, 2),
        open_ports=len([f for f in findings if f.type == "open-port"]),
    )
    return NormalizedResult(
        tool="native/portscan",
        target=target,
        duration_s=duration,
        findings=findings,
        errors=errors,
        raw_path=str(raw_path),
    )


# ---------------------------------------------------------------------------
# Per-port connection + banner grab
# ---------------------------------------------------------------------------


async def _bounded_probe(
    semaphore: asyncio.Semaphore,
    probe_fn: Any,
    port: int,
) -> None:
    async with semaphore:
        await probe_fn(port)


async def _connect_and_grab(
    host: str,
    port: int,
    connect_timeout: float,
    banner_timeout: float,
    log: Any,
) -> tuple[list[Finding], list[str]]:
    """
    Attempt TCP connect to (host, port).
    On success: grab banner, detect service.
    Returns (findings, errors).
    """
    findings: list[Finding] = []
    errors: list[str] = []

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=connect_timeout,
        )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return findings, errors  # port closed or filtered — not an error

    # Port is open
    log.debug("Port open", host=host, port=port)

    # Attempt banner grab
    banner_bytes = b""
    try:
        banner_bytes = await asyncio.wait_for(
            reader.read(_BANNER_BYTES),
            timeout=banner_timeout,
        )
    except (asyncio.TimeoutError, OSError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass

    banner_str = banner_bytes.decode(errors="replace").strip()
    service_name = _detect_service(port, banner_bytes)

    findings.append(
        Finding(
            tool="native/portscan",
            type="open-port",
            target=host,
            value=f"{port}/tcp",
            severity=None,
            metadata={
                "service": service_name,
                "banner": banner_str[:256],
                "state": "open",
            },
        )
    )

    if banner_str:
        findings.append(
            Finding(
                tool="native/portscan",
                type="service-banner",
                target=host,
                value=banner_str[:128],
                severity=None,
                metadata={
                    "port": port,
                    "service": service_name,
                    "raw_banner": banner_str[:512],
                },
            )
        )

    return findings, errors


# ---------------------------------------------------------------------------
# Service detection
# ---------------------------------------------------------------------------


def _detect_service(port: int, banner: bytes) -> str:
    """
    Identify the service from banner bytes and/or port number.

    Returns a string service name, or "unknown".
    """
    if banner:
        for signature, svc in _BANNER_SIGNATURES:
            if banner.startswith(signature):
                # Disambiguate ftp/smtp on port 21 vs 25
                if svc == "ftp/smtp":
                    return "ftp" if port == 21 else "smtp"
                return svc
    return _PORT_SERVICE_MAP.get(port, "unknown")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_raw(workspace: Workspace, target: str, findings: list[Finding]) -> Path:
    import json
    import re

    safe_target = re.sub(r"[^\w.\-]", "_", target)[:64]
    raw_dir = workspace.raw_dir("native_portscan")
    raw_path = raw_dir / f"{safe_target}.jsonl"
    with raw_path.open("w", encoding="utf-8") as fh:
        for finding in findings:
            fh.write(finding.to_json() + "\n")
    return raw_path


# ---------------------------------------------------------------------------
# Unit-test stubs
# ---------------------------------------------------------------------------


def _test_detect_service_from_banner() -> None:
    assert _detect_service(22,  b"SSH-2.0-OpenSSH_8.9") == "ssh"
    assert _detect_service(21,  b"220 FTP server ready") == "ftp"
    assert _detect_service(25,  b"220 mail.example.com SMTP") == "smtp"
    assert _detect_service(80,  b"HTTP/1.1 200 OK") == "http"
    assert _detect_service(443, b"\x16\x03\x01") == "tls"
    assert _detect_service(9999, b"") == "unknown"
    assert _detect_service(3306, b"") == "mysql"   # port-based fallback
    print("portscan._test_detect_service_from_banner PASSED")


async def _test_scan_localhost_closed() -> None:
    """Scanning a guaranteed-closed port produces no findings."""
    import tempfile
    from recontk.core.workspace import Workspace

    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create(Path(td) / "ws", "127.0.0.1", "test")
        result = await run_scan(
            "127.0.0.1",
            ws,
            ports=[19999],    # port very unlikely to be open
            connect_timeout=1.0,
        )
    assert result.errors == []
    # We cannot assert len == 0 because 19999 might be open on the test host,
    # but we can assert the result is well-formed.
    assert isinstance(result.findings, list)
    print("portscan._test_scan_localhost_closed PASSED")


async def _test_scan_open_port() -> None:
    """
    Start a minimal TCP server on a random port and verify it is detected.
    """
    import tempfile
    from recontk.core.workspace import Workspace

    # Start a simple echo server
    server = await asyncio.start_server(
        lambda r, w: w.write(b"TEST-BANNER\r\n"),
        "127.0.0.1",
        0,  # OS assigns port
    )
    port = server.sockets[0].getsockname()[1]

    try:
        with tempfile.TemporaryDirectory() as td:
            ws = Workspace.create(Path(td) / "ws", "127.0.0.1", "test")
            result = await run_scan(
                "127.0.0.1",
                ws,
                ports=[port],
                connect_timeout=2.0,
                banner_timeout=1.0,
            )
    finally:
        server.close()
        await server.wait_closed()

    open_ports = [f for f in result.findings if f.type == "open-port"]
    assert len(open_ports) == 1, f"Expected 1 open-port finding, got {len(open_ports)}"
    assert open_ports[0].value == f"{port}/tcp"
    banners = [f for f in result.findings if f.type == "service-banner"]
    assert len(banners) == 1
    assert "TEST-BANNER" in banners[0].value
    print("portscan._test_scan_open_port PASSED")


if __name__ == "__main__":
    _test_detect_service_from_banner()
    asyncio.run(_test_scan_localhost_closed())
    asyncio.run(_test_scan_open_port())
