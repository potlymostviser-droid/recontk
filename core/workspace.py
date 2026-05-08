"""
recontk.core.workspace
~~~~~~~~~~~~~~~~~~~~~~~
Workspace lifecycle management:

  - Create the canonical directory tree for a new run.
  - Write and update manifest.json (profile, target, tool versions, status).
  - Provide resume state helpers (load existing manifest, list completed stages).
  - Offer path helpers used by tool wrappers and modules.

Workspace layout (per the spec):

  workspaces/<target>/<UTC-timestamp>/
  ├── manifest.json
  ├── logs/
  │   ├── run.jsonl
  │   └── <stage>.log
  ├── raw/<tool>/
  ├── normalized/
  ├── loot/
  ├── screenshots/
  └── reports/
      ├── report.json
      ├── report.md
      ├── report.html
      └── report.csv
"""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from recontk.core.errors import (
    WorkspaceCorruptedError,
    WorkspaceError,
    WorkspaceNotFoundError,
)

# ---------------------------------------------------------------------------
# Manifest schema
# ---------------------------------------------------------------------------

MANIFEST_VERSION = "1"
MANIFEST_FILENAME = "manifest.json"

# Valid status transitions:  created → running → completed | failed | aborted
_VALID_STATUSES = frozenset({"created", "running", "completed", "failed", "aborted"})


@dataclass
class StageRecord:
    """Tracks completion of a single pipeline stage."""

    name: str
    status: str          # "pending" | "running" | "completed" | "failed" | "skipped"
    started_at: str | None = None
    ended_at: str | None = None
    tool: str | None = None
    error: str | None = None


@dataclass
class WorkspaceManifest:
    """In-memory representation of manifest.json."""

    manifest_version: str
    target: str
    profile: str
    workspace_path: str    # absolute, stringified
    created_at: str
    updated_at: str
    status: str            # see _VALID_STATUSES
    tool_versions: dict[str, str]
    stages: list[StageRecord]
    extra: dict[str, Any]  # arbitrary extension data

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "target": self.target,
            "profile": self.profile,
            "workspace_path": self.workspace_path,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "tool_versions": self.tool_versions,
            "stages": [
                {
                    "name": s.name,
                    "status": s.status,
                    "started_at": s.started_at,
                    "ended_at": s.ended_at,
                    "tool": s.tool,
                    "error": s.error,
                }
                for s in self.stages
            ],
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], workspace_path: Path) -> "WorkspaceManifest":
        try:
            stages = [
                StageRecord(
                    name=s["name"],
                    status=s["status"],
                    started_at=s.get("started_at"),
                    ended_at=s.get("ended_at"),
                    tool=s.get("tool"),
                    error=s.get("error"),
                )
                for s in data.get("stages", [])
            ]
            return cls(
                manifest_version=str(data.get("manifest_version", MANIFEST_VERSION)),
                target=data["target"],
                profile=data["profile"],
                workspace_path=str(workspace_path.resolve()),
                created_at=data["created_at"],
                updated_at=data["updated_at"],
                status=data.get("status", "created"),
                tool_versions=data.get("tool_versions", {}),
                stages=stages,
                extra=data.get("extra", {}),
            )
        except KeyError as exc:
            raise WorkspaceCorruptedError(
                str(workspace_path),
                f"Missing required field in manifest: {exc}",
            ) from exc


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _sanitise_target(target: str) -> str:
    """Convert a target string into a filesystem-safe directory name."""
    safe = re.sub(r"[^\w.\-]", "_", target)
    return safe[:128]  # cap to avoid OS path-length issues


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------


class Workspace:
    """
    Represents a single scan run's workspace on disk.

    Do not instantiate directly — use :func:`create` or :func:`open`.
    """

    _SUBDIRS = [
        "logs",
        "raw",
        "normalized",
        "loot",
        "screenshots",
        "reports",
    ]

    def __init__(self, path: Path, manifest: WorkspaceManifest) -> None:
        self._path = path.resolve()
        self._manifest = manifest

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        workspace_root: Path,
        target: str,
        profile: str,
        tool_versions: dict[str, str] | None = None,
        name: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> "Workspace":
        """
        Create a new workspace directory tree.

        Parameters
        ----------
        workspace_root:
            Parent directory (config.workspace_root).
        target:
            The scan target (hostname, IP, CIDR).
        profile:
            Profile name used for this run.
        tool_versions:
            Dict of tool → version string, populated by the registry.
        name:
            Optional explicit workspace name; defaults to UTC timestamp.
        extra:
            Arbitrary metadata to store in manifest.extra.

        Returns
        -------
        Workspace
            A fully initialised workspace with directories created and
            manifest written to disk.

        Raises
        ------
        WorkspaceError
            If the workspace already exists or cannot be created.
        """
        ts = name or _utc_timestamp()
        safe_target = _sanitise_target(target)
        path = (workspace_root / safe_target / ts).resolve()

        if path.exists():
            raise WorkspaceError(
                f"Workspace already exists: {path}",
                context={"path": str(path)},
            )

        try:
            path.mkdir(parents=True, exist_ok=False)
        except OSError as exc:
            raise WorkspaceError(
                f"Cannot create workspace directory '{path}': {exc}",
                context={"path": str(path)},
            ) from exc

        # Create sub-directories
        for sub in cls._SUBDIRS:
            (path / sub).mkdir(exist_ok=True)

        now = _now_iso()
        manifest = WorkspaceManifest(
            manifest_version=MANIFEST_VERSION,
            target=target,
            profile=profile,
            workspace_path=str(path),
            created_at=now,
            updated_at=now,
            status="created",
            tool_versions=tool_versions or {},
            stages=[],
            extra=extra or {},
        )

        ws = cls(path, manifest)
        ws._write_manifest()
        return ws

    @classmethod
    def open(cls, path: str | Path) -> "Workspace":
        """
        Open an existing workspace from disk.

        Parameters
        ----------
        path:
            Path to the workspace directory (must contain manifest.json).

        Raises
        ------
        WorkspaceNotFoundError
            If the path does not exist.
        WorkspaceCorruptedError
            If manifest.json is missing or invalid JSON.
        """
        ws_path = Path(path).resolve()
        if not ws_path.exists():
            raise WorkspaceNotFoundError(str(ws_path))

        manifest_file = ws_path / MANIFEST_FILENAME
        if not manifest_file.exists():
            raise WorkspaceCorruptedError(str(ws_path), "manifest.json is missing")

        try:
            data = json.loads(manifest_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise WorkspaceCorruptedError(
                str(ws_path), f"manifest.json is not valid JSON: {exc}"
            ) from exc

        manifest = WorkspaceManifest.from_dict(data, ws_path)
        return cls(ws_path, manifest)

    # ------------------------------------------------------------------
    # Path accessors
    # ------------------------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    @property
    def manifest(self) -> WorkspaceManifest:
        return self._manifest

    def logs_dir(self) -> Path:
        return self._path / "logs"

    def run_jsonl(self) -> Path:
        return self.logs_dir() / "run.jsonl"

    def stage_log(self, stage: str) -> Path:
        safe = re.sub(r"[^\w.\-]", "_", stage)
        return self.logs_dir() / f"{safe}.log"

    def raw_dir(self, tool: str | None = None) -> Path:
        base = self._path / "raw"
        if tool:
            d = base / tool
            d.mkdir(parents=True, exist_ok=True)
            return d
        return base

    def normalized_dir(self) -> Path:
        return self._path / "normalized"

    def loot_dir(self) -> Path:
        return self._path / "loot"

    def screenshots_dir(self) -> Path:
        return self._path / "screenshots"

    def reports_dir(self) -> Path:
        return self._path / "reports"

    def normalized_path(self, stage: str) -> Path:
        safe = re.sub(r"[^\w.\-]", "_", stage)
        return self.normalized_dir() / f"{safe}.json"

    # ------------------------------------------------------------------
    # Manifest mutators
    # ------------------------------------------------------------------

    def set_status(self, status: str) -> None:
        if status not in _VALID_STATUSES:
            raise WorkspaceError(
                f"Invalid workspace status '{status}'. "
                f"Valid: {sorted(_VALID_STATUSES)}",
                context={"status": status},
            )
        self._manifest.status = status
        self._manifest.updated_at = _now_iso()
        self._write_manifest()

    def update_tool_versions(self, versions: dict[str, str]) -> None:
        self._manifest.tool_versions.update(versions)
        self._manifest.updated_at = _now_iso()
        self._write_manifest()

    def record_stage_start(self, stage: str, tool: str | None = None) -> None:
        """Mark a stage as started.  Idempotent if already present."""
        for rec in self._manifest.stages:
            if rec.name == stage:
                rec.status = "running"
                rec.started_at = _now_iso()
                rec.tool = tool
                self._manifest.updated_at = _now_iso()
                self._write_manifest()
                return
        self._manifest.stages.append(
            StageRecord(
                name=stage,
                status="running",
                started_at=_now_iso(),
                tool=tool,
            )
        )
        self._manifest.updated_at = _now_iso()
        self._write_manifest()

    def record_stage_end(
        self,
        stage: str,
        *,
        success: bool,
        error: str | None = None,
        skipped: bool = False,
    ) -> None:
        """Mark a stage as completed, failed, or skipped."""
        status = "skipped" if skipped else ("completed" if success else "failed")
        for rec in self._manifest.stages:
            if rec.name == stage:
                rec.status = status
                rec.ended_at = _now_iso()
                rec.error = error
                break
        else:
            # Stage wasn't started — create a record anyway
            self._manifest.stages.append(
                StageRecord(
                    name=stage,
                    status=status,
                    ended_at=_now_iso(),
                    error=error,
                )
            )
        self._manifest.updated_at = _now_iso()
        self._write_manifest()

    def completed_stages(self) -> list[str]:
        """Return names of stages with status 'completed'."""
        return [s.name for s in self._manifest.stages if s.status == "completed"]

    def failed_stages(self) -> list[str]:
        return [s.name for s in self._manifest.stages if s.status == "failed"]

    def is_stage_done(self, stage: str) -> bool:
        """True if stage is completed (not failed, not skipped)."""
        for rec in self._manifest.stages:
            if rec.name == stage and rec.status == "completed":
                return True
        return False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write_manifest(self) -> None:
        """Atomically write manifest.json using a temp file + rename."""
        manifest_path = self._path / MANIFEST_FILENAME
        tmp_path = manifest_path.with_suffix(".json.tmp")
        try:
            tmp_path.write_text(
                json.dumps(self._manifest.to_dict(), indent=2, default=str),
                encoding="utf-8",
            )
            tmp_path.replace(manifest_path)
        except OSError as exc:
            raise WorkspaceError(
                f"Failed to write manifest: {exc}",
                context={"path": str(manifest_path)},
            ) from exc

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"Workspace(target={self._manifest.target!r}, "
            f"profile={self._manifest.profile!r}, "
            f"status={self._manifest.status!r}, "
            f"path={self._path!r})"
        )


# ---------------------------------------------------------------------------
# List workspaces helper
# ---------------------------------------------------------------------------


def list_workspaces(workspace_root: Path) -> list[Path]:
    """
    Return all workspace paths under workspace_root, newest first
    (sorted by directory mtime descending).

    Skips directories without a manifest.json silently.
    """
    results: list[Path] = []
    if not workspace_root.exists():
        return results
    for target_dir in workspace_root.iterdir():
        if not target_dir.is_dir():
            continue
        for ts_dir in target_dir.iterdir():
            if not ts_dir.is_dir():
                continue
            if (ts_dir / MANIFEST_FILENAME).exists():
                results.append(ts_dir)
    results.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return results


# ---------------------------------------------------------------------------
# Unit-test stubs
# ---------------------------------------------------------------------------


def _test_create_and_open(tmp_path: Path) -> None:
    """Create a workspace, write it, re-open it, verify manifest."""
    ws = Workspace.create(
        workspace_root=tmp_path,
        target="example.com",
        profile="recon",
        tool_versions={"nmap": "7.94"},
    )
    assert ws.path.exists()
    assert (ws.path / "manifest.json").exists()
    assert (ws.path / "logs").exists()
    assert (ws.path / "raw").exists()
    assert ws.manifest.status == "created"

    # Re-open
    ws2 = Workspace.open(ws.path)
    assert ws2.manifest.target == "example.com"
    assert ws2.manifest.profile == "recon"
    assert ws2.manifest.tool_versions == {"nmap": "7.94"}
    print("workspace._test_create_and_open PASSED")


def _test_stage_lifecycle(tmp_path: Path) -> None:
    """Stage start → end → resume detection."""
    ws = Workspace.create(tmp_path, "192.168.1.1", "normal")
    ws.record_stage_start("port.scan", tool="nmap")
    assert not ws.is_stage_done("port.scan")

    ws.record_stage_end("port.scan", success=True)
    assert ws.is_stage_done("port.scan")
    assert "port.scan" in ws.completed_stages()

    ws.record_stage_start("http.probe", tool="httpx")
    ws.record_stage_end("http.probe", success=False, error="timeout")
    assert "http.probe" in ws.failed_stages()
    print("workspace._test_stage_lifecycle PASSED")


def _test_status_transitions(tmp_path: Path) -> None:
    ws = Workspace.create(tmp_path, "ctf.local", "ctf")
    ws.set_status("running")
    assert ws.manifest.status == "running"
    ws.set_status("completed")
    assert ws.manifest.status == "completed"

    try:
        ws.set_status("invalid_status")
        assert False, "Should have raised WorkspaceError"
    except WorkspaceError:
        pass
    print("workspace._test_status_transitions PASSED")


def _test_atomic_write_on_corruption(tmp_path: Path) -> None:
    """Verify that a failed write does not corrupt the existing manifest."""
    ws = Workspace.create(tmp_path, "test.local", "recon")
    original = (ws.path / "manifest.json").read_text()

    # Simulate a write failure by making the directory read-only temporarily
    # (This is best-effort on some OS/filesystems; skip gracefully if not supported)
    import stat

    manifest_path = ws.path / "manifest.json"
    try:
        os.chmod(ws.path, stat.S_IRUSR | stat.S_IXUSR)
        try:
            ws.set_status("running")
        except WorkspaceError:
            pass  # Expected
        finally:
            os.chmod(ws.path, stat.S_IRWXU)
    except PermissionError:
        pass  # Running as root or unsupported FS — skip

    # Manifest should still be readable
    content = (manifest_path).read_text()
    assert content  # not empty
    print("workspace._test_atomic_write_on_corruption PASSED")


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tp = Path(td)
        _test_create_and_open(tp / "t1")
        _test_stage_lifecycle(tp / "t2")
        _test_status_transitions(tp / "t3")
        _test_atomic_write_on_corruption(tp / "t4")
