"""
recontk.modules.contentdiscovery
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Content discovery (directory/file brute-force) module.

Capabilities used:
  - content.discover (ffuf, gobuster)

Requires a wordlist.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from recontk.core.logging import StructuredLogger
    from recontk.core.runner import Runner

from recontk.models import NormalizedResult


async def run(
    target: str,
    runner: "Runner",
    logger: "StructuredLogger",
    wordlist: Path | None = None,
    **kwargs: Any,
) -> NormalizedResult:
    """
    Execute content discovery against ``target``.

    Parameters
    ----------
    wordlist:
        Path to a wordlist file.  If None, uses a default from config.wordlist_dir.
    """
    log = logger.bind(module="contentdiscovery", target=target)
    log.event("module_started")

    if wordlist is None:
        # Attempt to locate a default wordlist
        wordlist_dir = runner._config.wordlist_dir
        candidates = [
            wordlist_dir / "common.txt",
            wordlist_dir / "dirb-common.txt",
            wordlist_dir / "raft-small-words.txt",
        ]
        for candidate in candidates:
            if candidate.exists():
                wordlist = candidate
                break

    if wordlist is None or not wordlist.exists():
        log.warning("No wordlist found; skipping content discovery")
        return NormalizedResult(
            tool="contentdiscovery-module",
            target=target,
            duration_s=0.0,
            findings=[],
            errors=["No wordlist available"],
        )

    # Build extra_args for ffuf/gobuster
    # ffuf:     -w <wordlist> -u <target>/FUZZ
    # gobuster: -w <wordlist> -u <target>
    # We normalise by passing wordlist path via extra_args
    extra_args = ["-w", str(wordlist)]

    result = await runner.run(
        "content.discover",
        target,
        extra_args=extra_args,
        **kwargs,
    )

    log.event(
        "module_finished",
        path_count=result.finding_count,
        duration_s=round(result.duration_s, 2),
    )
    return result
