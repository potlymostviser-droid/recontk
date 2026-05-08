"""
recontk.tools.base
~~~~~~~~~~~~~~~~~~
Abstract base class for all external tool wrappers.

Every wrapper in recontk/tools/*.py must:
  1. Inherit from ToolWrapper.
  2. Implement build_cmd(), parse_output(), and TOOL_KEY / CAPABILITY.
  3. Return NormalizedResult from run() — never raise on tool failure;
     capture errors into NormalizedResult.errors instead.
  4. Use argument lists (no shell=True).
  5. Respect the rate limiter and proxy settings.
  6. Write raw tool output to workspace.raw_dir(TOOL_KEY) before parsing.

The base class provides:
  - run()         : async orchestration (rate-limit → subprocess → parse → normalise)
  - _exec()       : subprocess execution with timeout + output capture
  - _raw_path()   : path helper for raw output files
  - _proxy_env()  : build subprocess env with proxy settings injected
"""

from __future__ import annotations

import abc
import asyncio
import os
import time
from pathlib import Path
from typing import Any

from recontk.core.errors import ToolExecutionError, ToolTimeoutError
from recontk.core.logging import BoundStructuredLogger, StructuredLogger
from recontk.core.ratelimit import AsyncTokenBucket
from recontk.core.workspace import Workspace
from recontk.models import NormalizedResult


class ToolWrapper(abc.ABC):
    """
    Abstract base class for external tool wrappers.

    Subclasses must define:
      TOOL_KEY  : str — canonical tool name (matches registry key)
      CAPABILITY: str — primary capability this wrapper satisfies

    Subclasses must implement:
      build_cmd()    → list[str]
      parse_output() → list[Finding]
    """

    TOOL_KEY: str = ""
    CAPABILITY: str = ""

    def __init__(
        self,
        binary: str,
        workspace: Workspace,
        logger: StructuredLogger,
        rate_limiter: AsyncTokenBucket | None = None,
        timeout_s: float = 300.0,
        extra_args: list[str] | None = None,
        proxy: str | None = None,
        dry_run: bool = False,
    ) -> None:
        """
        Parameters
        ----------
        binary:
            Absolute path to the tool binary (from shutil.which or registry).
        workspace:
            Active Workspace instance; used for raw output paths.
        logger:
            Structured logger; will be bound with tool= and target= fields.
        rate_limiter:
            Optional token bucket; if provided, one token is acquired before
            each subprocess execution.
        timeout_s:
            Maximum wall-clock seconds for the subprocess.
        extra_args:
            Additional CLI flags appended to the command (profile overrides).
        proxy:
            HTTP proxy URL; injected into subprocess environment.
        dry_run:
            If True, build_cmd() is called and logged but subprocess is NOT
            executed.  Returns an empty NormalizedResult.
        """
        if not self.TOOL_KEY:
            raise TypeError(f"{type(self).__name__} must define TOOL_KEY")
        if not self.CAPABILITY:
            raise TypeError(f"{type(self).__name__} must define CAPABILITY")

        self._binary = binary
        self._workspace = workspace
        self._timeout_s = timeout_s
        self._extra_args = extra_args or []
        self._proxy = proxy
        self._dry_run = dry_run
        self._rate_limiter = rate_limiter

        self._log: BoundStructuredLogger = logger.bind(
            tool=self.TOOL_KEY,
        )

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        """
        Build the subprocess argument list.

        Rules:
          - First element MUST be self._binary (absolute path).
          - Must include a machine-readable output flag pointing to
            raw_output_path (e.g. -oX, -oJ, --json-output).
          - Append self._extra_args at the end.
          - Never use shell=True or string interpolation.
          - Never include the target in a way that allows shell injection
            (the argument list form of subprocess prevents this, but targets
            must still be validated by the caller before reaching here).

        Parameters
        ----------
        target:
            The scan target (hostname, IP, URL, CIDR).
        raw_output_path:
            Path where the tool should write its machine-readable output.

        Returns
        -------
        list[str]
            Complete argument list ready for subprocess.run / asyncio.
        """

    @abc.abstractmethod
    def parse_output(
        self,
        raw_output_path: Path,
        target: str,
    ) -> list[Any]:  # list[Finding]
        """
        Parse the tool's machine-readable output file into Finding objects.

        Rules:
          - Must read from raw_output_path (the untouched file on disk).
          - Must NOT scrape human-readable text when a structured format exists.
          - On parse error: return [] and let the caller record the error.
          - Never invent severity — use only what the tool provides.

        Parameters
        ----------
        raw_output_path:
            Path to the raw tool output file written during execution.
        target:
            Original scan target, for populating Finding.target.

        Returns
        -------
        list[Finding]
        """

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def run(self, target: str) -> NormalizedResult:
        """
        Full async execution pipeline:
          1. Acquire rate-limit token (if limiter is set).
          2. Build command.
          3. If dry_run: log and return empty result.
          4. Execute subprocess with timeout.
          5. Write raw output to workspace.
          6. Parse output into Findings.
          7. Return NormalizedResult.

        On tool failure (non-zero exit): records error in NormalizedResult.errors
        and returns whatever findings were parsed (partial results are useful).
        On timeout: records error and returns empty findings.

        Never raises ToolExecutionError or ToolTimeoutError — those are
        caught here and recorded as structured errors.
        """
        bound_log = self._log.bind(target=target)
        raw_path = self._raw_path(target)
        cmd = self.build_cmd(target, raw_path)

        bound_log.event(
            "tool_started",
            cmd=" ".join(cmd),
            dry_run=self._dry_run,
            timeout_s=self._timeout_s,
        )

        if self._dry_run:
            bound_log.info("Dry-run mode: skipping execution", cmd=cmd)
            return NormalizedResult(
                tool=self.TOOL_KEY,
                target=target,
                duration_s=0.0,
                findings=[],
                errors=[],
                raw_path=None,
            )

        # Rate limiting
        if self._rate_limiter is not None:
            await self._rate_limiter.acquire(1)

        start = time.monotonic()
        errors: list[str] = []

        try:
            returncode, stdout, stderr = await self._exec(cmd, target)
        except ToolTimeoutError as exc:
            duration = time.monotonic() - start
            bound_log.error("Tool timed out", timeout_s=self._timeout_s)
            return NormalizedResult(
                tool=self.TOOL_KEY,
                target=target,
                duration_s=duration,
                findings=[],
                errors=[str(exc)],
                raw_path=None,
            )
        except OSError as exc:
            duration = time.monotonic() - start
            bound_log.error("Tool OS error", error=str(exc))
            return NormalizedResult(
                tool=self.TOOL_KEY,
                target=target,
                duration_s=duration,
                findings=[],
                errors=[f"OSError: {exc}"],
                raw_path=None,
            )

        duration = time.monotonic() - start

        if returncode != 0:
            msg = f"Exited with code {returncode}: {stderr[:512]}"
            bound_log.warning("Tool exited non-zero", returncode=returncode, stderr=stderr[:256])
            errors.append(msg)
            # Do not return early — the tool may still have written partial output

        bound_log.event(
            "tool_finished",
            returncode=returncode,
            duration_s=round(duration, 2),
            raw_path=str(raw_path),
        )

        # Parse output
        findings = []
        if raw_path.exists() and raw_path.stat().st_size > 0:
            try:
                findings = self.parse_output(raw_path, target)
            except Exception as exc:  # noqa: BLE001
                parse_err = f"Output parse error: {exc}"
                bound_log.error("Failed to parse tool output", error=str(exc))
                errors.append(parse_err)
        else:
            bound_log.warning("Tool produced no output file or empty file")

        bound_log.info(
            "Tool results normalised",
            finding_count=len(findings),
            error_count=len(errors),
        )

        return NormalizedResult(
            tool=self.TOOL_KEY,
            target=target,
            duration_s=duration,
            findings=findings,
            errors=errors,
            raw_path=str(raw_path) if raw_path.exists() else None,
        )

    # ------------------------------------------------------------------
    # Subprocess execution
    # ------------------------------------------------------------------

    async def _exec(
        self,
        cmd: list[str],
        target: str,
    ) -> tuple[int, str, str]:
        """
        Execute cmd as an async subprocess.

        Returns
        -------
        (returncode, stdout, stderr)

        Raises
        ------
        ToolTimeoutError
            If the process exceeds self._timeout_s.
        OSError
            If the binary cannot be executed.
        """
        env = self._proxy_env()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except OSError:
            raise

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=self._timeout_s,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()  # reap the process
            raise ToolTimeoutError(self.TOOL_KEY, self._timeout_s)

        return (
            proc.returncode or 0,
            stdout_bytes.decode(errors="replace"),
            stderr_bytes.decode(errors="replace"),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _raw_path(self, target: str) -> Path:
        """
        Return the path where raw tool output should be written.

        Format: workspace/raw/<tool>/<sanitised-target>.<extension>
        Subclasses may override to change the extension.
        """
        import re

        safe_target = re.sub(r"[^\w.\-]", "_", target)[:64]
        raw_dir = self._workspace.raw_dir(self.TOOL_KEY)
        return raw_dir / f"{safe_target}{self._output_extension()}"

    def _output_extension(self) -> str:
        """
        File extension for raw output.  Override in subclasses that use
        formats other than JSON.  Default: '.json'
        """
        return ".json"

    def _proxy_env(self) -> dict[str, str]:
        """
        Build a subprocess environment dict with proxy settings merged in.
        Inherits the current process environment; overlays proxy if set.
        """
        env = os.environ.copy()
        if self._proxy:
            env["HTTP_PROXY"] = self._proxy
            env["HTTPS_PROXY"] = self._proxy
            env["http_proxy"] = self._proxy
            env["https_proxy"] = self._proxy
        return env

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"tool={self.TOOL_KEY!r}, "
            f"binary={self._binary!r}, "
            f"timeout_s={self._timeout_s})"
        )


# ---------------------------------------------------------------------------
# Unit-test stubs
# ---------------------------------------------------------------------------


class _EchoWrapper(ToolWrapper):
    """Minimal concrete wrapper for testing the base class."""

    TOOL_KEY = "echo"
    CAPABILITY = "test.echo"

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        import json as _json
        import shutil as _shutil

        echo = _shutil.which("echo") or "/bin/echo"
        # Write a fake JSON output file directly so parse_output has something
        raw_output_path.parent.mkdir(parents=True, exist_ok=True)
        raw_output_path.write_text(
            _json.dumps({"target": target, "result": "ok"}), encoding="utf-8"
        )
        return [echo, target]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        import json as _json
        from recontk.models import Finding

        data = _json.loads(raw_output_path.read_text())
        return [
            Finding(
                tool=self.TOOL_KEY,
                type="test.result",
                target=target,
                value=data.get("result", ""),
            )
        ]


async def _test_dry_run(tmp_path: Path) -> None:
    """dry_run=True must return empty NormalizedResult without executing."""
    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path, "test.local", "test")
    logger = get_null_logger()

    wrapper = _EchoWrapper(
        binary="/bin/echo",
        workspace=ws,
        logger=logger,
        dry_run=True,
    )
    result = await wrapper.run("test.local")
    assert result.finding_count == 0
    assert result.duration_s == 0.0
    assert result.raw_path is None
    print("base._test_dry_run PASSED")


async def _test_run_produces_findings(tmp_path: Path) -> None:
    """A real run must produce findings and write raw output."""
    import shutil as _shutil

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path, "test.local", "test")
    logger = get_null_logger()

    echo = _shutil.which("echo")
    if echo is None:
        print("base._test_run_produces_findings SKIPPED (echo not found)")
        return

    wrapper = _EchoWrapper(
        binary=echo,
        workspace=ws,
        logger=logger,
    )
    result = await wrapper.run("example.com")
    assert result.finding_count == 1
    assert result.findings[0].value == "ok"
    assert result.errors == []
    print("base._test_run_produces_findings PASSED")


if __name__ == "__main__":
    import asyncio
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tp = Path(td)
        asyncio.run(_test_dry_run(tp / "t1"))
        asyncio.run(_test_run_produces_findings(tp / "t2"))
