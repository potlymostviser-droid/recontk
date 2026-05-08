"""
recontk.native.dnsresolver
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Native DNS resolver using dnspython.

Capabilities : dns.resolve, dns.brute

dns.resolve:
  Resolves A, AAAA, CNAME, MX, NS, TXT, SOA records for a given host.
  Finding type: "dns-record"

dns.brute:
  Iterates a wordlist, prepends each word as a subdomain, resolves A/AAAA.
  Finding type: "subdomain" (on successful resolution)

Both return NormalizedResult.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import dns.asyncresolver          # dnspython >= 2.0
import dns.exception
import dns.rdatatype

from recontk.core.logging import StructuredLogger, get_null_logger
from recontk.core.ratelimit import AsyncTokenBucket
from recontk.core.workspace import Workspace
from recontk.models import Finding, NormalizedResult

# Record types queried during a full resolve pass
_RESOLVE_TYPES: list[str] = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]

# Default concurrency for brute-force
_BRUTE_CONCURRENCY = 50


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_resolver(
    nameservers: list[str] | None = None,
    timeout: float = 5.0,
) -> dns.asyncresolver.Resolver:
    """Build a dnspython async resolver with optional custom nameservers."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    if nameservers:
        resolver.nameservers = nameservers
    return resolver


async def _resolve_record(
    resolver: dns.asyncresolver.Resolver,
    host: str,
    rtype: str,
) -> list[str]:
    """
    Resolve ``host`` for record type ``rtype``.
    Returns list of string representations.  Never raises — returns [] on failure.
    """
    try:
        answer = await resolver.resolve(host, rtype, raise_on_no_answer=False)
        results: list[str] = []
        for rdata in answer:
            results.append(rdata.to_text())
        return results
    except (
        dns.exception.DNSException,
        dns.asyncresolver.NXDOMAIN,
        dns.asyncresolver.NoAnswer,
        dns.asyncresolver.NoNameservers,
        asyncio.TimeoutError,
        OSError,
    ):
        return []


# ---------------------------------------------------------------------------
# dns.resolve
# ---------------------------------------------------------------------------


async def run_resolve(
    target: str,
    workspace: Workspace,
    logger: StructuredLogger | None = None,
    nameservers: list[str] | None = None,
    timeout: float = 5.0,
    **_kwargs: Any,
) -> NormalizedResult:
    """
    Resolve all standard DNS record types for ``target``.

    Parameters
    ----------
    target:
        Hostname to resolve.
    workspace:
        Active workspace (used for raw output path).
    logger:
        Structured logger.
    nameservers:
        Optional list of resolver IPs.  Uses system resolver if None.
    timeout:
        Per-query timeout in seconds.
    """
    log = (logger or get_null_logger()).bind(
        tool="native/dnsresolver", target=target, capability="dns.resolve"
    )
    start = time.monotonic()
    log.event("tool_started")

    resolver = _make_resolver(nameservers, timeout)
    findings: list[Finding] = []
    errors: list[str] = []

    for rtype in _RESOLVE_TYPES:
        values = await _resolve_record(resolver, target, rtype)
        for value in values:
            findings.append(
                Finding(
                    tool="native/dnsresolver",
                    type="dns-record",
                    target=target,
                    value=value,
                    severity=None,
                    metadata={"record_type": rtype, "host": target},
                )
            )

    duration = time.monotonic() - start

    # Write raw output (JSON lines of findings)
    raw_path = _write_raw(workspace, "resolve", target, findings)

    log.event(
        "tool_finished",
        duration_s=round(duration, 2),
        finding_count=len(findings),
    )
    return NormalizedResult(
        tool="native/dnsresolver",
        target=target,
        duration_s=duration,
        findings=findings,
        errors=errors,
        raw_path=str(raw_path),
    )


# ---------------------------------------------------------------------------
# dns.brute
# ---------------------------------------------------------------------------


async def run_brute(
    target: str,
    workspace: Workspace,
    logger: StructuredLogger | None = None,
    wordlist_path: Path | None = None,
    nameservers: list[str] | None = None,
    timeout: float = 3.0,
    concurrency: int = _BRUTE_CONCURRENCY,
    rate_limiter: AsyncTokenBucket | None = None,
    **_kwargs: Any,
) -> NormalizedResult:
    """
    DNS brute-force subdomain enumeration.

    Parameters
    ----------
    target:
        Base domain (e.g. "example.com").
    workspace:
        Active workspace.
    logger:
        Structured logger.
    wordlist_path:
        Path to a newline-delimited wordlist.  If None, uses a tiny
        built-in list for testing purposes only.
    nameservers:
        Optional resolver IPs.
    timeout:
        Per-query timeout.
    concurrency:
        Maximum simultaneous DNS queries.
    rate_limiter:
        Optional token bucket applied before each query.
    """
    log = (logger or get_null_logger()).bind(
        tool="native/dnsresolver", target=target, capability="dns.brute"
    )
    start = time.monotonic()
    log.event("tool_started")

    words = _load_wordlist(wordlist_path)
    resolver = _make_resolver(nameservers, timeout)
    findings: list[Finding] = []
    errors: list[str] = []
    semaphore = asyncio.Semaphore(concurrency)

    async def probe(word: str) -> None:
        fqdn = f"{word}.{target}"
        async with semaphore:
            if rate_limiter is not None:
                await rate_limiter.acquire(1)
            # Resolve A first; fallback to AAAA
            for rtype in ("A", "AAAA"):
                values = await _resolve_record(resolver, fqdn, rtype)
                if values:
                    findings.append(
                        Finding(
                            tool="native/dnsresolver",
                            type="subdomain",
                            target=target,
                            value=fqdn,
                            severity=None,
                            metadata={
                                "addresses": values,
                                "record_type": rtype,
                                "source": "native/dnsresolver-brute",
                            },
                        )
                    )
                    break  # found on A; don't also add AAAA finding

    tasks = [probe(word) for word in words]
    await asyncio.gather(*tasks)

    duration = time.monotonic() - start
    raw_path = _write_raw(workspace, "brute", target, findings)

    log.event(
        "tool_finished",
        duration_s=round(duration, 2),
        words_tested=len(words),
        found=len(findings),
    )
    return NormalizedResult(
        tool="native/dnsresolver",
        target=target,
        duration_s=duration,
        findings=findings,
        errors=errors,
        raw_path=str(raw_path),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_wordlist(path: Path | None) -> list[str]:
    """Load words from file, stripping blank lines and # comments."""
    if path is not None and path.exists():
        words: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)
        return words
    # Minimal built-in list — useful for unit tests only
    return [
        "www", "mail", "ftp", "dev", "staging", "api",
        "admin", "test", "vpn", "ns1", "ns2", "smtp",
    ]


def _write_raw(
    workspace: Workspace,
    operation: str,
    target: str,
    findings: list[Finding],
) -> Path:
    """Write findings as JSONL to the raw directory."""
    import json
    import re

    safe_target = re.sub(r"[^\w.\-]", "_", target)[:64]
    raw_dir = workspace.raw_dir("native_dnsresolver")
    raw_path = raw_dir / f"{operation}_{safe_target}.jsonl"
    with raw_path.open("w", encoding="utf-8") as fh:
        for finding in findings:
            fh.write(finding.to_json() + "\n")
    return raw_path


# ---------------------------------------------------------------------------
# Unit-test stubs
# ---------------------------------------------------------------------------


async def _test_resolve_real_domain() -> None:
    """Resolve a known public domain — requires network access."""
    import tempfile

    from recontk.core.workspace import Workspace

    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create(Path(td), "example.com", "test")
        result = await run_resolve("example.com", ws)

    assert result.tool == "native/dnsresolver"
    a_records = [
        f for f in result.findings
        if f.metadata.get("record_type") == "A"
    ]
    assert len(a_records) >= 1, "Expected at least one A record for example.com"
    print("dnsresolver._test_resolve_real_domain PASSED")


async def _test_brute_builtin_wordlist() -> None:
    """Brute-force with built-in wordlist — requires network access."""
    import tempfile

    from recontk.core.workspace import Workspace

    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create(Path(td), "example.com", "test")
        result = await run_brute("example.com", ws, concurrency=5)

    assert result.tool == "native/dnsresolver"
    # www.example.com should resolve
    found_values = {f.value for f in result.findings}
    assert "www.example.com" in found_values, (
        f"Expected www.example.com in findings. Got: {found_values}"
    )
    print("dnsresolver._test_brute_builtin_wordlist PASSED")


async def _test_resolve_nxdomain() -> None:
    """NXDOMAIN produces no findings and no errors (handled gracefully)."""
    import tempfile

    from recontk.core.workspace import Workspace

    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create(Path(td), "nx.example.invalid", "test")
        result = await run_resolve("nx.example.invalid", ws)

    assert result.findings == []
    assert result.errors == []
    print("dnsresolver._test_resolve_nxdomain PASSED")


if __name__ == "__main__":
    asyncio.run(_test_resolve_real_domain())
    asyncio.run(_test_brute_builtin_wordlist())
    asyncio.run(_test_resolve_nxdomain())
