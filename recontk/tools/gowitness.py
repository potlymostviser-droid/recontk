"""
recontk.tools.gowitness
~~~~~~~~~~~~~~~~~~~~~~~~
Gowitness wrapper.

Capability  : screenshot
Output flag : --write-db  gowitness writes screenshots to a directory
              and a SQLite DB.  We use: gowitness scan single --write-db
              and query the DB for metadata.
              # VERIFY: gowitness JSON export flag — use `gowitness report`
              # subcommand if available; currently we parse the sqlite DB.

Finding types:
  "screenshot"  value = screenshot_path  metadata = {url, status_code, title}
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class GoWitnessWrapper(ToolWrapper):
    TOOL_KEY = "gowitness"
    CAPABILITY = "screenshot"

    def _output_extension(self) -> str:
        # We use a directory, not a single file; point to the DB path
        return ".db"

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        """
        gowitness scan single <url>
          --write-db        : write results to SQLite   (per gowitness --help)
          --db-path <path>  : SQLite DB path            (per gowitness --help)
          --screenshot-path : where PNGs are saved      (per gowitness --help)
          --timeout         : per-page timeout          (per gowitness --help)
        """
        screenshot_dir = raw_output_path.parent / "screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        return [
            self._binary,
            "scan", "single",               # subcommand  (per gowitness --help)
            target,
            "--write-db",
            "--db-path", str(raw_output_path),
            "--screenshot-path", str(screenshot_dir),
            "--timeout", str(int(self._timeout_s)),
            "--disable-logging",            # (per gowitness --help)
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        Query the gowitness SQLite DB for URL records.

        gowitness DB schema (per gowitness source / docs):
          table: urls
            id, url, final_url, response_code, title, screenshot_path

        # VERIFY: exact column names may differ between gowitness versions.
        """
        findings: list[Finding] = []
        if not raw_output_path.exists():
            return findings

        try:
            conn = sqlite3.connect(str(raw_output_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT url, final_url, response_code, title, screenshot_path "
                "FROM urls"
            )
            rows = cur.fetchall()
            conn.close()
        except sqlite3.Error as exc:
            raise ValueError(f"gowitness DB query failed: {exc}") from exc

        for row in rows:
            screenshot_path = row["screenshot_path"] or ""
            findings.append(
                Finding(
                    tool=self.TOOL_KEY,
                    type="screenshot",
                    target=target,
                    value=screenshot_path,
                    severity=None,
                    metadata={
                        "url": row["url"],
                        "final_url": row["final_url"] or "",
                        "status_code": row["response_code"],
                        "title": row["title"] or "",
                    },
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------


def _test_parse_db(tmp_path: Path) -> None:
    db_path = tmp_path / "gowitness.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE urls "
        "(id INTEGER PRIMARY KEY, url TEXT, final_url TEXT, "
        "response_code INTEGER, title TEXT, screenshot_path TEXT)"
    )
    conn.execute(
        "INSERT INTO urls VALUES (1, 'https://example.com', "
        "'https://example.com', 200, 'Example Domain', '/screenshots/example.png')"
    )
    conn.commit()
    conn.close()

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com", "test")
    wrapper = GoWitnessWrapper(
        binary="/usr/local/bin/gowitness",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(db_path, "https://example.com")
    assert len(findings) == 1
    assert findings[0].type == "screenshot"
    assert findings[0].metadata["status_code"] == 200
    assert findings[0].metadata["title"] == "Example Domain"
    print("gowitness._test_parse_db PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_db(Path(td))
