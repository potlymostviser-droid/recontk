
"""
recontk.core.errors
~~~~~~~~~~~~~~~~~~~
All custom exceptions used across the toolkit.  Every exception carries
a structured ``context`` dict so callers can serialise it directly into
run.jsonl without string-scraping.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class RecontkError(Exception):
    """Root exception for all toolkit errors."""

    def __init__(self, message: str, context: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = context or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "error_type": type(self).__name__,
            "message": self.message,
            "context": self.context,
        }


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class ConfigError(RecontkError):
    """Raised when a config file is missing, malformed, or fails validation."""


class ProfileNotFoundError(ConfigError):
    """Raised when a requested scan profile cannot be found."""

    def __init__(self, profile: str) -> None:
        super().__init__(
            f"Profile '{profile}' not found.",
            context={"profile": profile},
        )


# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------


class WorkspaceError(RecontkError):
    """Raised on workspace creation or access failures."""


class WorkspaceNotFoundError(WorkspaceError):
    """Raised when a referenced workspace path does not exist."""

    def __init__(self, path: str) -> None:
        super().__init__(
            f"Workspace not found: {path}",
            context={"path": path},
        )


class WorkspaceCorruptedError(WorkspaceError):
    """Raised when manifest.json is missing or invalid."""

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(
            f"Workspace manifest corrupt at '{path}': {reason}",
            context={"path": path, "reason": reason},
        )


# ---------------------------------------------------------------------------
# Safety / scope
# ---------------------------------------------------------------------------


class ScopeViolationError(RecontkError):
    """
    Raised when a target violates scope constraints (e.g. RFC1918 without
    --allow-private, or target list exceeds confirmation threshold).
    """

    def __init__(self, target: str, reason: str) -> None:
        super().__init__(
            f"Scope violation for '{target}': {reason}",
            context={"target": target, "reason": reason},
        )


class ConfirmationRequiredError(RecontkError):
    """Raised when a destructive/large operation requires --confirm."""

    def __init__(self, reason: str) -> None:
        super().__init__(
            f"Explicit --confirm required: {reason}",
            context={"reason": reason},
        )


# ---------------------------------------------------------------------------
# Tool / registry
# ---------------------------------------------------------------------------


class ToolNotFoundError(RecontkError):
    """Raised when a required tool binary is not on PATH."""

    def __init__(self, tool: str) -> None:
        super().__init__(
            f"Tool not found on PATH: '{tool}'",
            context={"tool": tool},
        )


class ToolExecutionError(RecontkError):
    """Raised when a subprocess tool exits with a non-zero return code."""

    def __init__(
        self,
        tool: str,
        returncode: int,
        stderr: str,
        cmd: list[str] | None = None,
    ) -> None:
        super().__init__(
            f"Tool '{tool}' exited with code {returncode}.",
            context={
                "tool": tool,
                "returncode": returncode,
                "stderr": stderr[:2048],  # cap to avoid bloating logs
                "cmd": cmd or [],
            },
        )


class ToolTimeoutError(RecontkError):
    """Raised when a subprocess tool exceeds its configured timeout."""

    def __init__(self, tool: str, timeout_s: float) -> None:
        super().__init__(
            f"Tool '{tool}' timed out after {timeout_s}s.",
            context={"tool": tool, "timeout_s": timeout_s},
        )


class CapabilityUnavailableError(RecontkError):
    """
    Raised when no tool or native backend can satisfy a required capability
    and the module cannot proceed.
    """

    def __init__(self, capability: str) -> None:
        super().__init__(
            f"No provider available for capability '{capability}'.",
            context={"capability": capability},
        )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class RunnerError(RecontkError):
    """Raised on orchestration-level failures (not individual tool failures)."""


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


class ReportError(RecontkError):
    """Raised when report generation fails."""


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class PluginError(RecontkError):
    """Raised when a plugin fails to load or register."""

    def __init__(self, plugin: str, reason: str) -> None:
        super().__init__(
            f"Plugin '{plugin}' error: {reason}",
            context={"plugin": plugin, "reason": reason},
        )


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class RateLimitError(RecontkError):
    """Raised when token acquisition fails (e.g. bucket destroyed)."""
