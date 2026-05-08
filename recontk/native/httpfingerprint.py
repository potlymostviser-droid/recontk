"""
recontk.native.httpfingerprint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Native HTTP fingerprinting using the httpx library (not the CLI tool).

Capabilities : http.probe, http.fingerprint

Probes a URL/host for:
  - HTTP status code, redirect chain
  - Response headers (Server, X-Powered-By, Content-Type, etc.)
  - Page title (regex; no DOM parsing dependency)
  - Technology hints from headers and body patterns
  - WAF detection heuristics from headers

Finding types:
  "http-probe"        value = final URL
  "http-fingerprint"  value = technology name  (one finding per detected tech)

All HTTP calls go through the httpx AsyncClient so that proxy settings
(HTTP_PROXY / HTTPS_PROXY) are respected automatically.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from recontk.core.logging import StructuredLogger, get_null_logger
from recontk.core.ratelimit import AsyncTokenBucket
from recontk.core.workspace import Workspace
from recontk.models import Finding, NormalizedResult

# ---------------------------------------------------------------------------
# Technology fingerprint patterns
# Header-based patterns: (header_name_lower, regex, technology_name)
# ---------------------------------------------------------------------------

_HEADER_TECH_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("server",          re.compile(r"nginx",         re.I), "nginx"),
    ("server",          re.compile(r"apache",        re.I), "Apache"),
    ("server",          re.compile(r"IIS",           re.I), "IIS"),
    ("server",          re.compile(r"lighttpd",      re.I), "lighttpd"),
    ("server",          re.compile(r"caddy",         re.I), "Caddy"),
    ("server",          re.compile(r"cloudflare",    re.I), "Cloudflare"),
    ("x-powered-by",    re.compile(r"PHP",           re.I), "PHP"),
    ("x-powered-by",    re.compile(r"ASP\.NET",      re.I), "ASP.NET"),
    ("x-powered-by",    re.compile(r"Express",       re.I), "Express.js"),
    ("x-generator",     re.compile(r"WordPress",     re.I), "WordPress"),
    ("x-generator",     re.compile(r"Drupal",        re.I), "Drupal"),
    ("x-drupal-cache",  re.compile(r"",              re.I), "Drupal"),
    ("x-wp-total",      re.compile(r"",              re.I), "WordPress"),
    ("cf-ray",          re.compile(r"",              re.I), "Cloudflare"),
    ("x-sucuri-id",     re.compile(r"",              re.I), "Sucuri WAF"),
    ("x-akamai-transformed", re.compile(r"",         re.I), "Akamai"),
]

# Body-based patterns: (regex, technology_name)
_BODY_TECH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'<meta[^>]+generator[^>]+WordPress', re.I), "WordPress"),
    (re.compile(r'Drupal\.settings',                  re.I), "Drupal"),
    (re.compile(r'Joomla!',                           re.I), "Joomla"),
    (re.compile(r'__VIEWSTATE',                       re.I), "ASP.NET"),
    (re.compile(r'react(?:\.js|\.min\.js)',           re.I), "React"),
    (re.compile(r'angular(?:\.js|\.min\.js|/core)',   re.I), "Angular"),
    (re.compile(r'vue(?:\.js|\.min\.js)',              re.I), "Vue.js"),
    (re.compile(r'jquery(?:\.min)?\.js',              re.I), "jQuery"),
    (re.compile(r'bootstrap(?:\.min)?\.css',          re.I), "Bootstrap"),
    (re.compile(r'wp-content/themes/',                re.I), "WordPress"),
    (re.compile(r'wp-includes/',                      re.I), "WordPress"),
    (re.compile(r'/sites/default/files/',             re.I), "Drupal"),
]

# WAF detection heuristics — header presence
_WAF_HEADER_PATTERNS: list[tuple[str, str]] = [
    ("cf-ray",              "Cloudflare"),
    ("x-sucuri-id",         "Sucuri"),
    ("x-sucuri-cache",      "Sucuri"),
    ("x-akamai-transformed","Akamai"),
    ("x-cdn",               "CDN (generic)"),
    ("x-iinfo",             "Incapsula"),
    ("x-amz-cf-id",         "AWS CloudFront"),
    ("x-azure-ref",         "Azure CDN"),
    ("server-timing",       None),   # not a WAF, but worth noting
]

# Title extraction regex
_TITLE_RE = re.compile(r"<title[^>]*>([^<]{0,256})</title>", re.I | re.S)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def run_probe(
    target: str,
    workspace: Workspace,
    logger: StructuredLogger | None = None,
    timeout: float = 15.0,
    follow_redirects: bool = True,
    max_redirects: int = 10,
    proxy: str | None = None,
    rate_limiter: AsyncTokenBucket | None = None,
    user_agent: str = "recontk/0.1 (authorized security scanner)",
    verify_ssl: bool = False,
    **_kwargs: Any,
) -> NormalizedResult:
    """
    Probe ``target`` over HTTP/HTTPS and fingerprint the response.

    Parameters
    ----------
    target:
        URL or hostname.  If no scheme is given, both http:// and https://
        are tried.
    workspace:
        Active workspace.
    logger:
        Structured logger.
    timeout:
        Per-request timeout in seconds.
    follow_redirects:
        Follow HTTP redirects.
    max_redirects:
        Maximum redirects to follow.
    proxy:
        Proxy URL (overrides environment).
    rate_limiter:
        Optional token bucket.
    user_agent:
        User-Agent header value.
    verify_ssl:
        If False, skip TLS certificate verification (common for internal
        targets).
    """
    log = (logger or get_null_logger()).bind(
        tool="native/httpfingerprint", target=target, capability="http.probe"
    )
    start = time.monotonic()
    log.event("tool_started")

    # Normalise target to a list of URLs to probe
    urls = _normalise_target(target)
    findings: list[Finding] = []
    errors: list[str] = []

    proxies: dict[str, str] | None = None
    if proxy:
        proxies = {"http://": proxy, "https://": proxy}

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=follow_redirects,
        max_redirects=max_redirects,
        verify=verify_ssl,
        proxies=proxies,  # type: ignore[arg-type]
        headers={"User-Agent": user_agent},
    ) as client:
        for url in urls:
            if rate_limiter is not None:
                await rate_limiter.acquire(1)
            url_findings, url_errors = await _probe_url(client, url, target, log)
            findings.extend(url_findings)
            errors.extend(url_errors)

    duration = time.monotonic() - start
    raw_path = _write_raw(workspace, target, findings)

    log.event("tool_finished", duration_s=round(duration, 2), finding_count=len(findings))
    return NormalizedResult(
        tool="native/httpfingerprint",
        target=target,
        duration_s=duration,
        findings=findings,
        errors=errors,
        raw_path=str(raw_path),
    )


# ---------------------------------------------------------------------------
# Per-URL probe
# ---------------------------------------------------------------------------


async def _probe_url(
    client: httpx.AsyncClient,
    url: str,
    original_target: str,
    log: Any,
) -> tuple[list[Finding], list[str]]:
    """Probe a single URL and return (findings, errors)."""
    findings: list[Finding] = []
    errors: list[str] = []

    try:
        response = await client.get(url)
    except httpx.TimeoutException as exc:
        errors.append(f"Timeout probing {url}: {exc}")
        return findings, errors
    except httpx.RequestError as exc:
        errors.append(f"Request error probing {url}: {exc}")
        return findings, errors

    headers = dict(response.headers)
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Attempt to read body (cap to 512 KB to avoid memory issues)
    try:
        body = response.text[:524288]
    except Exception:
        body = ""

    title = _extract_title(body)
    final_url = str(response.url)
    status_code = response.status_code

    log.debug("HTTP probe response", url=url, status=status_code, final_url=final_url)

    # --- Primary http-probe finding ---
    findings.append(
        Finding(
            tool="native/httpfingerprint",
            type="http-probe",
            target=original_target,
            value=final_url,
            severity=None,
            metadata={
                "status_code": status_code,
                "title": title,
                "server": headers_lower.get("server", ""),
                "content_type": headers_lower.get("content-type", ""),
                "content_length": headers_lower.get("content-length", ""),
                "x_powered_by": headers_lower.get("x-powered-by", ""),
                "redirect_chain": [str(r.url) for r in response.history],
                "headers": dict(headers_lower),
            },
        )
    )

    # --- Technology fingerprints ---
    detected_techs: set[str] = set()

    for header_name, pattern, tech_name in _HEADER_TECH_PATTERNS:
        header_value = headers_lower.get(header_name, "")
        # Empty pattern means header presence is sufficient
        if header_value and (not pattern.pattern or pattern.search(header_value)):
            detected_techs.add(tech_name)

    for pattern, tech_name in _BODY_TECH_PATTERNS:
        if pattern.search(body):
            detected_techs.add(tech_name)

    for tech_name in sorted(detected_techs):
        findings.append(
            Finding(
                tool="native/httpfingerprint",
                type="http-fingerprint",
                target=original_target,
                value=tech_name,
                severity=None,
                metadata={"url": final_url, "detection": "header+body-regex"},
            )
        )

    # --- WAF detection ---
    for waf_header, waf_name in _WAF_HEADER_PATTERNS:
        if waf_header in headers_lower and waf_name:
            findings.append(
                Finding(
                    tool="native/httpfingerprint",
                    type="waf-detected",
                    target=original_target,
                    value=waf_name,
                    severity=None,
                    metadata={"url": final_url, "header": waf_header},
                )
            )

    return findings, errors


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalise_target(target: str) -> list[str]:
    """
    Convert a target string into a list of URLs to probe.

    Rules:
      - If target already has a scheme (http:// or https://), use as-is.
      - Otherwise, try https:// first, then http://.
    """
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        return [target]
    return [f"https://{target}", f"http://{target}"]


def _extract_title(body: str) -> str:
    """Extract the HTML <title> tag content, or return empty string."""
    m = _TITLE_RE.search(body)
    if m:
        return m.group(1).strip().replace("\n", " ")[:256]
    return ""


def _write_raw(workspace: Workspace, target: str, findings: list[Finding]) -> "Any":
    """Write findings as JSONL to the raw directory."""
    import json
    import re
    from pathlib import Path

    safe_target = re.sub(r"[^\w.\-]", "_", target)[:64]
    raw_dir = workspace.raw_dir("native_httpfingerprint")
    raw_path = raw_dir / f"{safe_target}.jsonl"
    with raw_path.open("w", encoding="utf-8") as fh:
        for finding in findings:
            fh.write(finding.to_json() + "\n")
    return raw_path


# ---------------------------------------------------------------------------
# Unit-test stubs
# ---------------------------------------------------------------------------


async def _test_probe_local_server() -> None:
    """Probe a real endpoint — requires network access."""
    import tempfile
    from recontk.core.workspace import Workspace

    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create(Path(td) / "ws", "example.com", "test")
        result = await run_probe("https://example.com", ws, verify_ssl=True)

    probe_findings = [f for f in result.findings if f.type == "http-probe"]
    assert len(probe_findings) >= 1
    assert probe_findings[0].metadata["status_code"] == 200
    print("httpfingerprint._test_probe_local_server PASSED")


def _test_normalise_target() -> None:
    assert _normalise_target("https://example.com") == ["https://example.com"]
    assert _normalise_target("example.com") == [
        "https://example.com", "http://example.com"
    ]
    assert _normalise_target("http://10.0.0.1:8080") == ["http://10.0.0.1:8080"]
    print("httpfingerprint._test_normalise_target PASSED")


def _test_extract_title() -> None:
    assert _extract_title("<html><title>Hello World</title></html>") == "Hello World"
    assert _extract_title("<html><title>  Spaces  </title></html>") == "Spaces"
    assert _extract_title("<html><body>No title</body></html>") == ""
    assert _extract_title("<TITLE>Upper</TITLE>") == "Upper"
    print("httpfingerprint._test_extract_title PASSED")


def _test_tech_detection_headers() -> None:
    """Verify header-based technology detection logic."""
    import json as _json

    # Build a fake response-like object isn't needed — test the pattern list directly
    headers_lower = {
        "server": "nginx/1.24.0",
        "x-powered-by": "PHP/8.2",
        "cf-ray": "7a1b2c3d-LHR",
    }
    body = ""
    detected: set[str] = set()
    for header_name, pattern, tech_name in _HEADER_TECH_PATTERNS:
        header_value = headers_lower.get(header_name, "")
        if header_value and (not pattern.pattern or pattern.search(header_value)):
            detected.add(tech_name)
    assert "nginx" in detected, f"nginx not detected: {detected}"
    assert "PHP" in detected, f"PHP not detected: {detected}"
    assert "Cloudflare" in detected, f"Cloudflare not detected: {detected}"
    print("httpfingerprint._test_tech_detection_headers PASSED")


if __name__ == "__main__":
    from pathlib import Path

    _test_normalise_target()
    _test_extract_title()
    _test_tech_detection_headers()
    asyncio.run(_test_probe_local_server())
