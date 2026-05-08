"""
recontk.core.runner
~~~~~~~~~~~~~~~~~~~~
Async orchestration engine that executes tools and native backends.

Core responsibilities:
  1. Resolve capability → provider using the registry.
  2. Instantiate ToolWrapper or call native backend run() function.
  3. Apply rate limiting, proxy settings, timeouts from config.
  4. Capture NormalizedResult and write to workspace.normalized/.
  5. Surface structured events to the logger.

The runner is capability-centric:
  - Modules request capabilities, not specific tools.
  - The runner selects the provider transparently.
  - If multiple providers are available, modules can request all via run_multi().
"""

from __future__ import annotations

import importlib
import time
from pathlib import Path
from typing import Any

from recontk.core.config import RecontkConfig
from recontk.core.errors import CapabilityUnavailableError, ToolNotFoundError
from recontk.core.logging import StructuredLogger
from recontk.core.ratelimit import make_limiter_from_config
from recontk.core.registry import ToolRegistry
from recontk.core.workspace import Workspace
from recontk.models import NormalizedResult
from recontk.tools.base import ToolWrapper


class Runner:
    """
    Capability-driven tool and native backend orchestrator.

    Usage::

        runner = Runner(
            registry=registry,
            workspace=workspace,
            config=config,
            logger=logger,
        )

        result = await runner.run(
            capability="port.scan",
            target="10.0.0.1",
        )

        # Or run all available providers and merge results:
        merged = await runner.run_multi(
            capability="subdomain.enum",
            target="example.com",
        )
    """

    def __init__(
        self,
        registry: ToolRegistry,
        workspace: Workspace,
        config: RecontkConfig,
        logger: StructuredLogger,
    ) -> None:
        self._registry = registry
        self._workspace = workspace
        self._config = config
        self._logger = logger

        # Build a shared rate limiter from config
        self._rate_limiter = make_limiter_from_config(
            rate=config.rate_limit.requests_per_second,
            burst=config.rate_limit.burst,
            sync=False,
        )

    # ------------------------------------------------------------------
    # Single-provider execution
    # ------------------------------------------------------------------

    async def run(
        self,
        capability: str,
        target: str,
        extra_args: list[str] | None = None,
        **kwargs: Any,
    ) -> NormalizedResult:
        """
        Run the first available provider for ``capability`` against ``target``.

        Parameters
        ----------
        capability:
            One of the capability keys in CAPABILITY_MAP (e.g. "port.scan").
        target:
            The scan target (hostname, IP, URL, etc.).
        extra_args:
            Additional CLI arguments (for tool wrappers only).
        **kwargs:
            Additional provider-specific parameters (e.g. wordlist_path,
            ports, concurrency).

        Returns
        -------
        NormalizedResult

        Raises
        ------
        CapabilityUnavailableError
            If no provider is available for this capability.
        """
        provider = self._registry.resolve(capability, self._logger)
        if provider is None:
            raise CapabilityUnavailableError(capability)

        self._logger.info(
            "Executing capability",
            capability=capability,
            provider=provider,
            target=target,
        )
        start = time.monotonic()

        result = await self._run_provider(
            provider=provider,
            capability=capability,
            target=target,
            extra_args=extra_args,
            **kwargs,
        )

        duration = time.monotonic() - start
        self._logger.event(
            "capability_executed",
            capability=capability,
            provider=provider,
            target=target,
            duration_s=round(duration, 2),
            finding_count=result.finding_count,
            error_count=len(result.errors),
        )

        # Write normalized result to workspace
        self._save_result(capability, result)
        return result

    # ------------------------------------------------------------------
    # Multi-provider execution (all available)
    # ------------------------------------------------------------------

    async def run_multi(
        self,
        capability: str,
        target: str,
        extra_args: list[str] | None = None,
        **kwargs: Any,
    ) -> NormalizedResult:
        """
        Run ALL available providers for ``capability`` and merge results.

        Findings are deduplicated by their deterministic ID.
        Errors are concatenated.
        Duration is the sum of all provider durations.

        Use this when you want maximum coverage (e.g. subdomain enumeration
        from subfinder + amass + native).
        """
        providers = self._registry.resolve_all(capability, self._logger)
        if not providers:
            raise CapabilityUnavailableError(capability)

        self._logger.info(
            "Executing multi-provider capability",
            capability=capability,
            providers=providers,
            target=target,
        )

        merged_result: NormalizedResult | None = None

        for provider in providers:
            try:
                result = await self._run_provider(
                    provider=provider,
                    capability=capability,
                    target=target,
                    extra_args=extra_args,
                    **kwargs,
                )
                if merged_result is None:
                    merged_result = result
                else:
                    merged_result.merge(result)
            except Exception as exc:  # noqa: BLE001
                self._logger.error(
                    "Multi-provider execution failed for one provider",
                    capability=capability,
                    provider=provider,
                    error=str(exc),
                )
                # Continue with other providers

        if merged_result is None:
            # All providers failed; return empty result
            merged_result = NormalizedResult(
                tool="multi-provider",
                target=target,
                duration_s=0.0,
                findings=[],
                errors=["All providers failed"],
            )

        self._save_result(capability, merged_result)
        return merged_result

    # ------------------------------------------------------------------
    # Internal: provider execution dispatcher
    # ------------------------------------------------------------------

    async def _run_provider(
        self,
        provider: str,
        capability: str,
        target: str,
        extra_args: list[str] | None = None,
        **kwargs: Any,
    ) -> NormalizedResult:
        """
        Execute a single provider (tool or native).

        Returns
        -------
        NormalizedResult
        """
        if provider.startswith("native/"):
            return await self._run_native(provider, capability, target, **kwargs)
        else:
            return await self._run_tool(provider, target, extra_args, **kwargs)

    # ------------------------------------------------------------------
    # Tool wrapper execution
    # ------------------------------------------------------------------

    async def _run_tool(
        self,
        tool_key: str,
        target: str,
        extra_args: list[str] | None = None,
        **kwargs: Any,
    ) -> NormalizedResult:
        """Instantiate a ToolWrapper and call run()."""
        tool_info = self._registry.require(tool_key)
        wrapper_class = self._load_wrapper_class(tool_key)

        timeout_s = self._get_tool_timeout(tool_key)
        proxy = self._config.proxy.https or self._config.proxy.http
        dry_run = self._config.safety.dry_run

        wrapper = wrapper_class(
            binary=tool_info.binary,
            workspace=self._workspace,
            logger=self._logger,
            rate_limiter=self._rate_limiter,
            timeout_s=timeout_s,
            extra_args=extra_args or [],
            proxy=proxy,
            dry_run=dry_run,
        )

        result = await wrapper.run(target)
        return result

    def _load_wrapper_class(self, tool_key: str) -> type[ToolWrapper]:
        """
        Dynamically import and return the ToolWrapper subclass for ``tool_key``.

        Convention: recontk.tools.<tool_key> exports a class named
        <CapitalizedToolKey>Wrapper.
        Special cases: httpx → HttpxWrapper, testssl.sh → TestsslWrapper.
        """
        module_name = tool_key.replace(".", "_").replace("-", "_")
        class_name = self._wrapper_class_name(tool_key)

        try:
            mod = importlib.import_module(f"recontk.tools.{module_name}")
            wrapper_class = getattr(mod, class_name)
            return wrapper_class  # type: ignore[return-value]
        except (ImportError, AttributeError) as exc:
            raise ToolNotFoundError(tool_key) from exc

    def _wrapper_class_name(self, tool_key: str) -> str:
        """Build the expected class name from tool_key."""
        mapping: dict[str, str] = {
            "httpx": "HttpxWrapper",
            "testssl.sh": "TestsslWrapper",
            "wafw00f": "Wafw00fWrapper",
            "whois": "WhoisWrapper",
            "theHarvester": "TheHarvesterWrapper",
        }
        if tool_key in mapping:
            return mapping[tool_key]
        # Default: capitalize and append Wrapper
        return f"{tool_key.capitalize()}Wrapper"

    def _get_tool_timeout(self, tool_key: str) -> float:
        """Return the configured timeout for a tool, or task_timeout_s as fallback."""
        timeouts = self._config.tool_timeouts
        tool_timeout = getattr(timeouts, tool_key.replace(".", "_").replace("-", "_"), None)
        if tool_timeout is not None:
            return float(tool_timeout)
        return self._config.concurrency.task_timeout_s

    # ------------------------------------------------------------------
    # Native backend execution
    # ------------------------------------------------------------------

    async def _run_native(
        self,
        provider: str,
        capability: str,
        target: str,
        **kwargs: Any,
    ) -> NormalizedResult:
        """
        Call a native backend's async run_*() function.

        Convention: recontk.native.<backend> exports run_<operation>().
        Example: native/dnsresolver → recontk.native.dnsresolver.run_resolve()
                 or run_brute() depending on capability.
        """
        backend_name = provider.split("/", 1)[1]  # "native/dnsresolver" → "dnsresolver"
        module_name = f"recontk.native.{backend_name}"

        # Map capability → function name
        func_name = self._native_func_name(backend_name, capability)

        try:
            mod = importlib.import_module(module_name)
            run_func = getattr(mod, func_name)
        except (ImportError, AttributeError) as exc:
            raise CapabilityUnavailableError(capability) from exc

        # Pass workspace, logger, rate_limiter, config-derived kwargs
        result = await run_func(
            target=target,
            workspace=self._workspace,
            logger=self._logger,
            rate_limiter=self._rate_limiter,
            proxy=self._config.proxy.https or self._config.proxy.http,
            timeout=self._config.concurrency.task_timeout_s,
            **kwargs,
        )
        return result

    def _native_func_name(self, backend_name: str, capability: str) -> str:
        """
        Map (backend, capability) → function name.

        Examples:
          (dnsresolver, dns.resolve) → run_resolve
          (dnsresolver, dns.brute)   → run_brute
          (portscan, port.scan)      → run_scan
          (httpfingerprint, http.probe) → run_probe
          (tlsinspect, tls.inspect)  → run_inspect
          (screenshot, screenshot)   → run_screenshot
        """
        mapping: dict[tuple[str, str], str] = {
            ("dnsresolver", "dns.resolve"): "run_resolve",
            ("dnsresolver", "dns.brute"): "run_brute",
            ("dnsresolver", "subdomain.enum"): "run_brute",
            ("portscan", "port.scan"): "run_scan",
            ("portscan", "service.detect"): "run_scan",
            ("httpfingerprint", "http.probe"): "run_probe",
            ("httpfingerprint", "http.fingerprint"): "run_probe",
            ("tlsinspect", "tls.inspect"): "run_inspect",
            ("screenshot", "screenshot"): "run_screenshot",
        }
        key = (backend_name, capability)
        if key in mapping:
            return mapping[key]
        # Fallback: "run_<last_part_of_capability>"
        return f"run_{capability.split('.')[-1]}"

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save_result(self, capability: str, result: NormalizedResult) -> None:
        """Write NormalizedResult as JSON to workspace.normalized_dir()."""
        path = self._workspace.normalized_path(capability)
        result.save(path)
        self._logger.debug(
            "Normalized result saved",
            capability=capability,
            path=str(path),
        )


# ---------------------------------------------------------------------------
# Unit-test stubs
# ---------------------------------------------------------------------------


async def _test_runner_basic() -> None:
    """Verify runner can resolve and execute a capability."""
    import tempfile
    from recontk.core.config import RecontkConfig
    from recontk.core.logging import get_null_logger
    from recontk.core.registry import ToolRegistry
    from recontk.core.workspace import Workspace

    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create(Path(td) / "ws", "example.com", "test")
        cfg = RecontkConfig()
        registry = ToolRegistry()
        registry._detected = True  # bypass detection for test
        registry._tools = {}  # no tools — will use native fallback
        logger = get_null_logger()

        runner = Runner(registry, ws, cfg, logger)
        result = await runner.run(
            capability="dns.resolve",
            target="example.com",
        )

    assert result.tool == "native/dnsresolver"
    assert result.target == "example.com"
    # We expect at least one A record for example.com
    a_records = [f for f in result.findings if f.metadata.get("record_type") == "A"]
    assert len(a_records) >= 1, f"Expected A records, got {len(a_records)}"
    print("runner._test_runner_basic PASSED")


if __name__ == "__main__":
    import asyncio
    asyncio.run(_test_runner_basic())
