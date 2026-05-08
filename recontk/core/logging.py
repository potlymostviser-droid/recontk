"""
recontk.core.logging
~~~~~~~~~~~~~~~~~~~~~
Structured logger that simultaneously writes:
  • Human-readable output  → Rich console (stderr)
  • Machine-readable lines → JSONL file  (run.jsonl)

Design rules:
  - One logger instance per run (passed explicitly; no global state).
  - Every log call produces a JSON object in run.jsonl; fields are stable.
  - Rich output honours NO_COLOR and is suppressed when stdout is not a TTY.
  - Severity levels map 1-to-1 to Python stdlib logging levels so external
    log consumers can parse them without a custom schema.

JSONL schema (one object per line):
  {
    "ts":      "<ISO8601>",
    "level":   "DEBUG|INFO|WARNING|ERROR|CRITICAL",
    "event":   "<short human message>",
    "module":  "<dotted module name>",
    "<key>":   <any extra structured field passed as kwargs>
  }
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from rich.console import Console
from rich.logging import RichHandler

# ---------------------------------------------------------------------------
# Level helpers
# ---------------------------------------------------------------------------

_LEVEL_STYLES: dict[str, str] = {
    "DEBUG": "dim",
    "INFO": "bold green",
    "WARNING": "bold yellow",
    "ERROR": "bold red",
    "CRITICAL": "bold white on red",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# ---------------------------------------------------------------------------
# JSONL handler
# ---------------------------------------------------------------------------


class JsonlHandler(logging.Handler):
    """
    Appends one JSON object per log record to an open text stream.
    Thread-safe via the handler's built-in lock.
    """

    def __init__(self, stream: TextIO) -> None:
        super().__init__()
        self._stream = stream

    def emit(self, record: logging.LogRecord) -> None:
        try:
            obj: dict[str, Any] = {
                "ts": _now_iso(),
                "level": record.levelname,
                "event": record.getMessage(),
                "module": record.name,
            }
            # Attach any extra structured fields stored by the logger
            extra = getattr(record, "_structured", {})
            obj.update(extra)
            line = json.dumps(obj, default=str)
            self.acquire()
            try:
                self._stream.write(line + "\n")
                self._stream.flush()
            finally:
                self.release()
        except Exception:  # noqa: BLE001
            self.handleError(record)


# ---------------------------------------------------------------------------
# StructuredLogger
# ---------------------------------------------------------------------------


class StructuredLogger:
    """
    Thin wrapper around a stdlib Logger that:
      1. Accepts arbitrary keyword arguments and stores them as structured
         fields in run.jsonl.
      2. Forwards to a Rich console handler for human output.
      3. Can be re-used across threads/coroutines (handlers are thread-safe).

    Usage::

        logger = StructuredLogger.create(
            name="recontk.run",
            jsonl_path=workspace / "logs" / "run.jsonl",
            verbose=True,
        )
        logger.info("Scan started", target="example.com", profile="recon")
        logger.error("Tool failed", tool="nmap", returncode=1)
    """

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        name: str = "recontk",
        jsonl_path: Path | None = None,
        verbose: bool = False,
        force_no_color: bool = False,
    ) -> "StructuredLogger":
        """
        Build a StructuredLogger with Rich console output + optional JSONL sink.

        Parameters
        ----------
        name:
            Logger name (appears in ``module`` field of JSONL records).
        jsonl_path:
            If given, JSONL records are appended to this file.  The parent
            directory must already exist.
        verbose:
            When True, sets the level to DEBUG; otherwise INFO.
        force_no_color:
            Disable Rich markup even when a TTY is detected.
        """
        level = logging.DEBUG if verbose else logging.INFO

        log = logging.getLogger(name)
        log.setLevel(level)
        # Avoid duplicate handlers when called multiple times (e.g. in tests)
        log.handlers.clear()
        log.propagate = False

        # --- Rich console handler (stderr) ---
        no_color = force_no_color or not sys.stderr.isatty()
        console = Console(
            stderr=True,
            no_color=no_color,
            highlight=False,
        )
        rich_handler = RichHandler(
            console=console,
            show_time=True,
            show_path=verbose,
            rich_tracebacks=True,
            markup=False,
        )
        rich_handler.setLevel(level)
        log.addHandler(rich_handler)

        # --- JSONL file handler ---
        if jsonl_path is not None:
            jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            stream = open(jsonl_path, "a", encoding="utf-8")  # noqa: WPS515
            jsonl_handler = JsonlHandler(stream)
            jsonl_handler.setLevel(logging.DEBUG)  # capture everything to file
            log.addHandler(jsonl_handler)

        return cls(log)

    # ------------------------------------------------------------------
    # Logging methods — all accept **fields for structured extras
    # ------------------------------------------------------------------

    def _log(self, level: int, msg: str, **fields: Any) -> None:
        """Internal dispatcher that attaches structured fields to the record."""
        # We use a custom attribute on the LogRecord to pass structured data
        # through to JsonlHandler without touching the formatted message.
        extra = {"_structured": fields}
        self._logger.log(level, msg, extra=extra, stacklevel=3)

    def debug(self, msg: str, **fields: Any) -> None:
        self._log(logging.DEBUG, msg, **fields)

    def info(self, msg: str, **fields: Any) -> None:
        self._log(logging.INFO, msg, **fields)

    def warning(self, msg: str, **fields: Any) -> None:
        self._log(logging.WARNING, msg, **fields)

    def error(self, msg: str, **fields: Any) -> None:
        self._log(logging.ERROR, msg, **fields)

    def critical(self, msg: str, **fields: Any) -> None:
        self._log(logging.CRITICAL, msg, **fields)

    def event(self, event_type: str, **fields: Any) -> None:
        """
        Log a structured event that does not map cleanly to a severity level
        (e.g. tool_started, finding_recorded).  Written at INFO level to the
        console; always written to JSONL.
        """
        self._log(logging.INFO, event_type, event_type=event_type, **fields)

    # ------------------------------------------------------------------
    # Context helper
    # ------------------------------------------------------------------

    def bind(self, **defaults: Any) -> "BoundStructuredLogger":
        """
        Return a child logger that always includes ``defaults`` as structured
        fields.  Useful for tool wrappers::

            tool_log = logger.bind(tool="nmap", target="10.0.0.1")
            tool_log.info("Starting scan")
        """
        return BoundStructuredLogger(self, defaults)

    # ------------------------------------------------------------------
    # Passthrough
    # ------------------------------------------------------------------

    @property
    def underlying(self) -> logging.Logger:
        return self._logger


class BoundStructuredLogger:
    """A StructuredLogger view that prefixes every call with fixed fields."""

    def __init__(self, parent: StructuredLogger, defaults: dict[str, Any]) -> None:
        self._parent = parent
        self._defaults = defaults

    def _merge(self, fields: dict[str, Any]) -> dict[str, Any]:
        return {**self._defaults, **fields}

    def debug(self, msg: str, **fields: Any) -> None:
        self._parent.debug(msg, **self._merge(fields))

    def info(self, msg: str, **fields: Any) -> None:
        self._parent.info(msg, **self._merge(fields))

    def warning(self, msg: str, **fields: Any) -> None:
        self._parent.warning(msg, **self._merge(fields))

    def error(self, msg: str, **fields: Any) -> None:
        self._parent.error(msg, **self._merge(fields))

    def critical(self, msg: str, **fields: Any) -> None:
        self._parent.critical(msg, **self._merge(fields))

    def event(self, event_type: str, **fields: Any) -> None:
        self._parent.event(event_type, **self._merge(fields))

    def bind(self, **extra: Any) -> "BoundStructuredLogger":
        return BoundStructuredLogger(self._parent, {**self._defaults, **extra})


# ---------------------------------------------------------------------------
# Module-level convenience (for modules that don't receive a logger instance)
# ---------------------------------------------------------------------------

_NULL_LOGGER = StructuredLogger(logging.getLogger("recontk.null"))
_NULL_LOGGER.underlying.addHandler(logging.NullHandler())


def get_null_logger() -> StructuredLogger:
    """Return a no-op logger for use in unit tests."""
    return _NULL_LOGGER


# ---------------------------------------------------------------------------
# Unit-test stubs
# ---------------------------------------------------------------------------


def _test_jsonl_output(tmp_path: Path) -> None:
    """Verify that log calls produce parseable JSONL."""
    import tempfile

    jsonl_file = tmp_path / "run.jsonl"
    logger = StructuredLogger.create(
        name="test.logging",
        jsonl_path=jsonl_file,
        verbose=True,
        force_no_color=True,
    )
    logger.info("test event", tool="nmap", target="127.0.0.1")
    logger.error("something failed", returncode=1)

    lines = jsonl_file.read_text().splitlines()
    assert len(lines) == 2, f"Expected 2 lines, got {len(lines)}"

    first = json.loads(lines[0])
    assert first["event"] == "test event"
    assert first["tool"] == "nmap"
    assert first["level"] == "INFO"

    second = json.loads(lines[1])
    assert second["returncode"] == 1
    print("logging._test_jsonl_output PASSED")


def _test_bound_logger(tmp_path: Path) -> None:
    jsonl_file = tmp_path / "bound.jsonl"
    logger = StructuredLogger.create(
        name="test.bound",
        jsonl_path=jsonl_file,
        force_no_color=True,
    )
    bound = logger.bind(tool="subfinder")
    bound.info("resolved", count=5)

    record = json.loads(jsonl_file.read_text().splitlines()[0])
    assert record["tool"] == "subfinder"
    assert record["count"] == 5
    print("logging._test_bound_logger PASSED")


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tp = Path(td)
        _test_jsonl_output(tp)
        _test_bound_logger(tp)
