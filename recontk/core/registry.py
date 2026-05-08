"""
recontk.core.registry
~~~~~~~~~~~~~~~~~~~~~~
Tool detection, capability mapping, and provider resolution.

On startup:
  1. For each known tool binary: shutil.which() + ``--version`` probe
     (5-second timeout, stderr captured).
  2. Cache results to ~/.cache/recontk/registry.json.
  3. Expose resolve(capability) → provider name or None.
  4. Log every resolution decision to the run logger.

Capability → ordered provider list (first available wins):

  dns.resolve      → [dnsx, dig, native/dnsresolver]
  dns.brute        → [dnsx, native/dnsresolver]
  subdomain.enum   → [subfinder, amass, native/dnsresolver]
  port.scan        → [nmap, masscan, naabu, native/portscan]
  service.detect   → [nmap, native/portscan]
  http.probe       → [httpx, native/httpfingerprint]
  http.fingerprint → [whatweb, wafw00f, native/httpfingerprint]
  screenshot       → [gowitness, native/screenshot]
  tls.inspect      → [testssl.sh, sslyze, native/tlsinspect]
  content.discover → [ffuf, gobuster]
  vuln.scan        → [nuclei]
  osint.harvest    → [theHarvester, gau, waybackurls]
  whois            → [whois, native/python-whois]
  asn.lookup       → [whois]   # VERIFY: confirm whois ASN flag support per distro

Native providers are handled by recontk.native.* modules.
Tool wrappers are handled by recontk.tools.* modules.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from recontk.core.errors import ToolNotFoundError
from recontk.core.logging import StructuredLogger, get_null_logger

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CACHE_DIR = Path.home() / ".cache" / "recontk"
_CACHE_FILE = _CACHE_DIR / "registry.json"
_VERSION_TIMEOUT_S = 5.0

# Tool binary names (what shutil.which() searches for)
_TOOL_BINARIES: dict[str, str] = {
    "nmap": "nmap",
    "masscan": "masscan",
    "subfinder": "subfinder",
    "amass": "amass",
    "httpx": "httpx",
    "nuclei": "nuclei",
    "naabu": "naabu",
    "gowitness": "gowitness",
    "whatweb": "whatweb",
    "wafw00f": "wafw00f",
    "dnsx": "dnsx",
    "gau": "gau",
    "waybackurls": "waybackurls",
    "ffuf": "ffuf",
    "gobuster": "gobuster",
    "testssl.sh": "testssl.sh",
    "sslyze": "sslyze",
    "theHarvester": "theHarvester",
    "whois": "whois",
    "dig": "dig",
}

# Per-tool version flags — most tools use --version; exceptions listed here.
# per each tool's --help / man page
_VERSION_FLAGS: dict[str, list[str]] = {
    "nmap": ["--version"],
    "masscan": ["--version"],
    "subfinder": ["-version"],       # per subfinder --help
    "amass": ["version"],            # per amass --help (subcommand, not flag)
    "httpx": ["-version"],           # per httpx --help
    "nuclei": ["-version"],          # per nuclei --help
    "naabu": ["-version"],           # per naabu --help
    "gowitness": ["version"],        # per gowitness --help (subcommand)
    "whatweb": ["--version"],
    "wafw00f": "--version".split(),
    "dnsx": ["-version"],            # per dnsx --help
    "gau": ["--version"],
    "waybackurls": [],               # VERIFY: waybackurls has no --version flag; use presence only
    "ffuf": ["-V"],                  # per ffuf --help
    "gobuster": ["version"],         # per gobuster --help (subcommand)
    "testssl.sh": ["--version"],
    "sslyze": ["--version"],
    "theHarvester": ["--version"],
    "whois": ["--version"],
    "dig": ["-v"],                   # per dig man page
}

# Capability → ordered list of providers (tool names or native/ identifiers)
CAPABILITY_MAP: dict[str, list[str]] = {
    "dns.resolve": ["dnsx", "dig", "native/dnsresolver"],
    "dns.brute": ["dnsx", "native/dnsresolver"],
    "subdomain.enum": ["subfinder", "amass", "native/dnsresolver"],
    "port.scan": ["nmap", "masscan", "naabu", "native/portscan"],
    "service.detect": ["nmap", "native/portscan"],
    "http.probe": ["httpx", "native/httpfingerprint"],
    "http.fingerprint": ["whatweb", "wafw00f", "native/httpfingerprint"],
    "screenshot": ["gowitness", "native/screenshot"],
    "tls.inspect": ["testssl.sh", "sslyze", "native/tlsinspect"],
    "content.discover": ["ffuf", "gobuster"],
    "vuln.scan": ["nuclei"],
    "osint.harvest": ["theHarvester", "gau", "waybackurls"],
    "whois": ["whois", "native/python-whois"],
    "asn.lookup": ["whois"],  # VERIFY: whois ASN flag varies by distro/version
}

# Native providers — these are always "available" from the registry's perspective;
# the native modules themselves handle unavailability (e.g. playwright missing).
_NATIVE_PROVIDERS = frozenset(
    {
        "native/dnsresolver",
        "native/portscan",
        "native/httpfingerprint",
        "native/screenshot",
        "native/tlsinspect",
        "native/python-whois",
    }
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ToolInfo:
    """Detection result for a single tool binary."""

    name: str
    binary: str              # resolved absolute path (from shutil.which)
    available: bool
    version: str | None      # raw version string from the tool
    version_flag: list[str]  # flags used to probe the version
    detected_at: str         # ISO8601


@dataclass
class RegistrySnapshot:
    """Persisted cache of detection results."""

    generated_at: str
    tools: dict[str, ToolInfo] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "tools": {
                name: {
                    "name": t.name,
                    "binary": t.binary,
                    "available": t.available,
                    "version": t.version,
                    "version_flag": t.version_flag,
                    "detected_at": t.detected_at,
                }
                for name, t in self.tools.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RegistrySnapshot":
        tools: dict[str, ToolInfo] = {}
        for name, td in data.get("tools", {}).items():
            tools[name] = ToolInfo(
                name=td["name"],
                binary=td.get("binary", ""),
                available=td.get("available", False),
                version=td.get("version"),
                version_flag=td.get("version_flag", []),
                detected_at=td.get("detected_at", ""),
            )
        return cls(generated_at=data.get("generated_at", ""), tools=tools)


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _probe_tool(binary_name: str, tool_key: str) -> ToolInfo:
    """
    Run shutil.which() then attempt a version probe.

    Parameters
    ----------
    binary_name:
        The executable name to search for on PATH.
    tool_key:
        The canonical tool key used in the registry (may differ from binary,
        e.g. "testssl.sh").

    Returns
    -------
    ToolInfo
        Populated with detection results; never raises.
    """
    version_flags = _VERSION_FLAGS.get(tool_key, ["--version"])
    which_result = shutil.which(binary_name)

    if which_result is None:
        return ToolInfo(
            name=tool_key,
            binary="",
            available=False,
            version=None,
            version_flag=version_flags,
            detected_at=_now_iso(),
        )

    # Tool is on PATH — try to get its version string
    version: str | None = None
    if version_flags:  # waybackurls has no version flag
        cmd = [which_result] + version_flags
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_VERSION_TIMEOUT_S,
            )
            # Most tools print version to stdout; some to stderr
            output = (proc.stdout or proc.stderr or "").strip()
            # Take only the first non-empty line to keep it compact
            for line in output.splitlines():
                stripped = line.strip()
                if stripped:
                    version = stripped[:256]  # cap length
                    break
        except (subprocess.TimeoutExpired, OSError):
            # Tool exists but version probe failed — still mark as available
            version = None

    return ToolInfo(
        name=tool_key,
        binary=which_result,
        available=True,
        version=version,
        version_flag=version_flags,
        detected_at=_now_iso(),
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class ToolRegistry:
    """
    Central tool detection and capability resolution service.

    Usage::

        registry = ToolRegistry()
        registry.detect(logger=logger)          # or registry.load_cache()

        provider = registry.resolve("port.scan")
        # provider is a tool key like "nmap" or "native/portscan", or None
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolInfo] = {}
        self._detected: bool = False

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def detect(
        self,
        logger: StructuredLogger | None = None,
        force: bool = False,
    ) -> None:
        """
        Probe all known tools and populate the internal registry.
        Results are cached to ~/.cache/recontk/registry.json.

        Parameters
        ----------
        logger:
            Optional structured logger; uses null logger if not provided.
        force:
            If True, bypasses the on-disk cache and re-probes all tools.
        """
        log = logger or get_null_logger()

        if not force and self._try_load_cache(log):
            return

        log.info("Probing installed tools", tool_count=len(_TOOL_BINARIES))
        start = time.monotonic()

        for tool_key, binary_name in _TOOL_BINARIES.items():
            info = _probe_tool(binary_name, tool_key)
            self._tools[tool_key] = info
            log.debug(
                "Tool probed",
                tool=tool_key,
                available=info.available,
                version=info.version,
                binary=info.binary,
            )

        elapsed = time.monotonic() - start
        available = sum(1 for t in self._tools.values() if t.available)
        log.info(
            "Tool detection complete",
            available=available,
            total=len(self._tools),
            elapsed_s=round(elapsed, 2),
        )

        self._detected = True
        self._write_cache(log)

    def _try_load_cache(self, log: StructuredLogger) -> bool:
        """
        Attempt to load from on-disk cache.  Returns True on success.
        Cache is considered stale after 24 hours.
        """
        if not _CACHE_FILE.exists():
            return False

        try:
            data = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
            snapshot = RegistrySnapshot.from_dict(data)

            # Staleness check: 86400 seconds = 24 hours
            generated = datetime.fromisoformat(snapshot.generated_at)
            age_s = (
                datetime.now(timezone.utc) - generated.replace(tzinfo=timezone.utc)
            ).total_seconds()
            if age_s > 86400:
                log.debug("Registry cache is stale, re-detecting", age_s=age_s)
                return False

            self._tools = snapshot.tools
            self._detected = True
            log.debug(
                "Registry loaded from cache",
                cache_path=str(_CACHE_FILE),
                age_s=round(age_s, 0),
            )
            return True

        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            log.warning("Registry cache corrupt; re-detecting", error=str(exc))
            return False

    def _write_cache(self, log: StructuredLogger) -> None:
        """Persist current detection results to disk."""
        try:
            _CACHE_DIR.mkdir(parents=True, exist_ok=True)
            snapshot = RegistrySnapshot(
                generated_at=_now_iso(),
                tools=self._tools,
            )
            tmp = _CACHE_FILE.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps(snapshot.to_dict(), indent=2, default=str),
                encoding="utf-8",
            )
            tmp.replace(_CACHE_FILE)
            log.debug("Registry cache written", path=str(_CACHE_FILE))
        except OSError as exc:
            log.warning("Failed to write registry cache", error=str(exc))

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def resolve(
        self,
        capability: str,
        logger: StructuredLogger | None = None,
    ) -> str | None:
        """
        Return the first available provider for ``capability``, or None.

        Provider strings are either a tool key (e.g. "nmap") or a native
        backend identifier (e.g. "native/portscan").

        Every resolution decision is logged as a structured event.

        Parameters
        ----------
        capability:
            One of the keys in CAPABILITY_MAP.
        logger:
            Optional logger; uses null logger if not provided.

        Returns
        -------
        str | None
            Provider key, or None if no provider is available.
        """
        log = logger or get_null_logger()

        if not self._detected:
            raise RuntimeError(
                "ToolRegistry.detect() must be called before resolve(). "
                "Call registry.detect(logger) at startup."
            )

        providers = CAPABILITY_MAP.get(capability)
        if providers is None:
            log.warning("Unknown capability requested", capability=capability)
            return None

        for provider in providers:
            available = self._is_provider_available(provider)
            if available:
                log.event(
                    "capability_resolved",
                    capability=capability,
                    provider=provider,
                )
                return provider

        log.warning(
            "No provider available for capability",
            capability=capability,
            candidates=providers,
        )
        return None

    def resolve_all(
        self,
        capability: str,
        logger: StructuredLogger | None = None,
    ) -> list[str]:
        """
        Return ALL available providers for a capability (not just the first).
        Useful when a module wants to run multiple tools and merge results.
        """
        log = logger or get_null_logger()
        providers = CAPABILITY_MAP.get(capability, [])
        available = [p for p in providers if self._is_provider_available(p)]
        log.debug(
            "All providers resolved",
            capability=capability,
            available=available,
        )
        return available

    def _is_provider_available(self, provider: str) -> bool:
        """Return True if the provider is usable."""
        if provider.startswith("native/"):
            # Native providers are always considered available from the
            # registry's perspective; the native module itself handles
            # optional dependency checks (e.g. playwright).
            return provider in _NATIVE_PROVIDERS
        tool_info = self._tools.get(provider)
        return tool_info is not None and tool_info.available

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    def tool_info(self, tool_key: str) -> ToolInfo | None:
        return self._tools.get(tool_key)

    def available_tools(self) -> list[ToolInfo]:
        return [t for t in self._tools.values() if t.available]

    def missing_tools(self) -> list[ToolInfo]:
        return [t for t in self._tools.values() if not t.available]

    def capability_table(self) -> dict[str, str | None]:
        """
        Return a snapshot dict of capability → resolved provider (or None).
        Used by `recontk doctor` to display the capability matrix.
        """
        if not self._detected:
            return {}
        return {cap: self._first_available(providers) for cap, providers in CAPABILITY_MAP.items()}

    def _first_available(self, providers: list[str]) -> str | None:
        for p in providers:
            if self._is_provider_available(p):
                return p
        return None

    def versions(self) -> dict[str, str | None]:
        """Return a dict of tool → version string (or None if not available)."""
        return {
            name: (info.version if info.available else None)
            for name, info in self._tools.items()
        }

    def require(self, tool_key: str) -> ToolInfo:
        """
        Return ToolInfo for a tool that must be present.

        Raises
        ------
        ToolNotFoundError
            If the tool is not available.
        """
        info = self._tools.get(tool_key)
        if info is None or not info.available:
            raise ToolNotFoundError(tool_key)
        return info

    # ------------------------------------------------------------------
    # Cache invalidation
    # ------------------------------------------------------------------

    def invalidate_cache(self) -> None:
        """Delete the on-disk cache, forcing re-detection on next startup."""
        if _CACHE_FILE.exists():
            _CACHE_FILE.unlink()
        self._detected = False
        self._tools = {}


# ---------------------------------------------------------------------------
# Module-level singleton (initialised lazily)
# ---------------------------------------------------------------------------

_registry: ToolRegistry | None = None


def get_registry() -> ToolRegistry:
    """
    Return the module-level ToolRegistry singleton.

    Callers must call ``.detect()`` on the returned registry if it has not
    yet been initialised.  The CLI (cli.py) is responsible for calling
    ``detect()`` at startup.
    """
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry


# ---------------------------------------------------------------------------
# Unit-test stubs
# ---------------------------------------------------------------------------


def _test_probe_missing_tool() -> None:
    """A tool not on PATH is correctly marked unavailable."""
    info = _probe_tool(
        binary_name="__recontk_nonexistent_tool_xyz__",
        tool_key="__nonexistent__",
    )
    assert not info.available
    assert info.binary == ""
    assert info.version is None
    print("registry._test_probe_missing_tool PASSED")


def _test_resolve_before_detect_raises() -> None:
    """resolve() before detect() must raise RuntimeError."""
    reg = ToolRegistry()
    try:
        reg.resolve("port.scan")
        assert False, "Should have raised RuntimeError"
    except RuntimeError:
        pass
    print("registry._test_resolve_before_detect_raises PASSED")


def _test_native_providers_always_available() -> None:
    """Native providers resolve as available without binary probing."""
    reg = ToolRegistry()
    # Manually set _detected to True and leave _tools empty
    reg._detected = True
    reg._tools = {}
    provider = reg.resolve("http.probe")
    # httpx binary is not in _tools, so it falls through to native/httpfingerprint
    assert provider == "native/httpfingerprint", f"Got: {provider}"
    print("registry._test_native_providers_always_available PASSED")


def _test_capability_table_structure() -> None:
    """capability_table() returns an entry for every known capability."""
    reg = ToolRegistry()
    reg._detected = True
    reg._tools = {}
    table = reg.capability_table()
    for cap in CAPABILITY_MAP:
        assert cap in table, f"Missing capability: {cap}"
    print("registry._test_capability_table_structure PASSED")


if __name__ == "__main__":
    _test_probe_missing_tool()
    _test_resolve_before_detect_raises()
    _test_native_providers_always_available()
    _test_capability_table_structure()
