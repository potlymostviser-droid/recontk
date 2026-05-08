"""
recontk.native.screenshot
~~~~~~~~~~~~~~~~~~~~~~~~~~
Native screenshot backend using Playwright (optional dependency).

Capability : screenshot

If playwright is not installed, run() returns a NormalizedResult with an
error explaining that neither gowitness nor playwright is available.
The caller (module layer) is responsible for checking capability availability
before calling this.

Finding types:
  "screenshot"  value = screenshot file path  metadata = {url, title, status}
"""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from typing import Any

from recontk.core.logging import StructuredLogger, get_null_logger
from recontk.core.ratelimit import AsyncTokenBucket
from recontk.core.workspace import Workspace
from recontk.models import Finding, NormalizedResult

# Playwright is an optional dependency
try:
    from playwright.async_api import async_playwright, Browser, Page
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

_DEFAULT_TIMEOUT_MS = 30_000   # 30 seconds per page (Playwright uses ms)
_DEFAULT_VIEWPORT = {"width": 1280, "height": 800}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def run_screenshot(
    target: str,
    workspace: Workspace,
    logger: StructuredLogger | None = None,
    timeout_ms: int = _DEFAULT_TIMEOUT_MS,
    proxy: str | None = None,
    rate_limiter: AsyncTokenBucket | None = None,
    user_agent: str = "recontk/0.1 (authorized security scanner)",
    viewport: dict[str, int] | None = None,
    **_kwargs: Any,
) -> NormalizedResult:
    """
    Capture a screenshot of ``target`` using Playwright (Chromium headless).

    Parameters
    ----------
    target:
        URL or hostname.  If no scheme, https:// is tried first.
    workspace:
        Active workspace; screenshots are saved to workspace.screenshots_dir().
    logger:
        Structured logger.
    timeout_ms:
        Per-page navigation timeout in milliseconds.
    proxy:
        Proxy URL (e.g. "http://127.0.0.1:8080").
    rate_limiter:
        Optional token bucket.
    user_agent:
        Browser User-Agent string.
    viewport:
        Browser viewport dict with "width" and "height" keys.
    """
    log = (logger or get_null_logger()).bind(
        tool="native/screenshot", target=target, capability="screenshot"
    )
    start = time.monotonic()
    log.event("tool_started")

    if not _PLAYWRIGHT_AVAILABLE:
        duration = time.monotonic() - start
        return NormalizedResult(
            tool="native/screenshot",
            target=target,
            duration_s=duration,
            findings=[],
            errors=[
                "Playwright is not installed. "
                "Install with: pip install 'recontk[screenshot]' "
                "then run: playwright install chromium"
            ],
            raw_path=None,
        )

    if rate_limiter is not None:
        await rate_limiter.acquire(1)

    url = _normalise_url(target)
    vp = viewport or _DEFAULT_VIEWPORT
    findings: list[Finding] = []
    errors: list[str] = []

    proxy_config: dict[str, str] | None = None
    if proxy:
        proxy_config = {"server": proxy}

    try:
        async with async_playwright() as pw:
            browser_args: dict[str, Any] = {
                "headless": True,
                "args": ["--no-sandbox", "--disable-dev-shm-usage"],
            }
            if proxy_config:
                browser_args["proxy"] = proxy_config

            browser: Browser = await pw.chromium.launch(**browser_args)

            context = await browser.new_context(
                user_agent=user_agent,
                viewport=vp,
                ignore_https_errors=True,  # common for internal targets
            )
            page: Page = await context.new_page()

            try:
                response = await page.goto(
                    url,
                    timeout=timeout_ms,
                    wait_until="domcontentloaded",
                )
                status = response.status if response else 0
                title = await page.title()
                final_url = page.url

                # Save screenshot
                screenshot_path = _screenshot_path(workspace, target)
                await page.screenshot(path=str(screenshot_path), full_page=False)

                findings.append(
                    Finding(
                        tool="native/screenshot",
                        type="screenshot",
                        target=target,
                        value=str(screenshot_path),
                        severity=None,
                        metadata={
                            "url": final_url,
                            "original_url": url,
                            "title": title,
                            "status_code": status,
                        },
                    )
                )
                log.info(
                    "Screenshot captured",
                    url=final_url,
                    status=status,
                    path=str(screenshot_path),
                )
            except Exception as page_exc:
                # Try http:// if https:// failed and target had no explicit scheme
                if url.startswith("https://") and "://" not in target:
                    http_url = "http://" + target
                    try:
                        response = await page.goto(
                            http_url,
                            timeout=timeout_ms,
                            wait_until="domcontentloaded",
                        )
                        status = response.status if response else 0
                        title = await page.title()
                        final_url = page.url
                        screenshot_path = _screenshot_path(workspace, target)
                        await page.screenshot(path=str(screenshot_path), full_page=False)
                        findings.append(
                            Finding(
                                tool="native/screenshot",
                                type="screenshot",
                                target=target,
                                value=str(screenshot_path),
                                severity=None,
                                metadata={
                                    "url": final_url,
                                    "original_url": http_url,
                                    "title": title,
                                    "status_code": status,
                                },
                            )
                        )
                    except Exception as fallback_exc:
                        errors.append(f"Screenshot failed: {fallback_exc}")
                else:
                    errors.append(f"Screenshot failed: {page_exc}")

            finally:
                await context.close()
                await browser.close()

    except Exception as exc:
        errors.append(f"Playwright error: {exc}")

    duration = time.monotonic() - start
    log.event("tool_finished", duration_s=round(duration, 2), finding_count=len(findings))
    return NormalizedResult(
        tool="native/screenshot",
        target=target,
        duration_s=duration,
        findings=findings,
        errors=errors,
        raw_path=None,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalise_url(target: str) -> str:
    """Add https:// scheme if no scheme is present."""
    if target.startswith(("http://", "https://")):
        return target
    return f"https://{target}"


def _screenshot_path(workspace: Workspace, target: str) -> Path:
    """Build a filesystem-safe path for the screenshot PNG."""
    safe = re.sub(r"[^\w.\-]", "_", target)[:64]
    path = workspace.screenshots_dir() / f"{safe}.png"
    return path


# ---------------------------------------------------------------------------
# Unit-test stubs
# ---------------------------------------------------------------------------


def _test_normalise_url() -> None:
    assert _normalise_url("example.com") == "https://example.com"
    assert _normalise_url("http://example.com") == "http://example.com"
    assert _normalise_url("https://example.com/path") == "https://example.com/path"
    print("screenshot._test_normalise_url PASSED")


def _test_unavailable_returns_error() -> None:
    """When playwright is absent the result contains an error."""
    import unittest.mock as mock
    import tempfile
    from recontk.core.workspace import Workspace

    with mock.patch("recontk.native.screenshot._PLAYWRIGHT_AVAILABLE", False):
        with tempfile.TemporaryDirectory() as td:
            ws = Workspace.create(Path(td) / "ws", "example.com", "test")
            result = asyncio.run(run_screenshot("example.com", ws))
        assert result.findings == []
        assert len(result.errors) == 1
        assert "Playwright" in result.errors[0]
    print("screenshot._test_unavailable_returns_error PASSED")


async def _test_screenshot_real_site() -> None:
    """Capture example.com — requires network + playwright install."""
    import tempfile
    from recontk.core.workspace import Workspace

    if not _PLAYWRIGHT_AVAILABLE:
        print("screenshot._test_screenshot_real_site SKIPPED (playwright not installed)")
        return

    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create(Path(td) / "ws", "example.com", "test")
        result = await run_screenshot("example.com", ws)

    if result.errors:
        print(f"screenshot._test_screenshot_real_site WARNING: {result.errors}")
        return

    assert len(result.findings) == 1
    png_path = Path(result.findings[0].value)
    assert png_path.exists(), f"Screenshot file not found: {png_path}"
    assert png_path.stat().st_size > 0
    print("screenshot._test_screenshot_real_site PASSED")


if __name__ == "__main__":
    _test_normalise_url()
    _test_unavailable_returns_error()
    asyncio.run(_test_screenshot_real_site())
