"""
recontk.reporting.exporter
~~~~~~~~~~~~~~~~~~~~~~~~~~
Report generation engine.

Reads normalized findings from workspace.normalized_dir(), aggregates them,
and renders output in the requested format.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from recontk.core.workspace import Workspace, WorkspaceManifest
from recontk.models import Finding, NormalizedResult


class ReportExporter:
    """
    Multi-format report generator.

    Usage::

        exporter = ReportExporter(workspace)
        exporter.export_json(output_path)
        exporter.export_markdown(output_path)
        exporter.export_html(output_path)
        exporter.export_csv(output_path)
    """

    def __init__(self, workspace: Workspace) -> None:
        self._workspace = workspace
        self._manifest = workspace.manifest
        self._findings: list[Finding] = []
        self._results_by_stage: dict[str, NormalizedResult] = {}
        self._load_findings()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load_findings(self) -> None:
        """Load all normalized results from workspace."""
        normalized_dir = self._workspace.normalized_dir()
        if not normalized_dir.exists():
            return

        for result_file in normalized_dir.glob("*.json"):
            try:
                result = NormalizedResult.load(result_file)
                stage_name = result_file.stem
                self._results_by_stage[stage_name] = result
                self._findings.extend(result.findings)
            except Exception:  # noqa: BLE001, S110
                # Silently skip corrupt files — logged during scan
                pass

    # ------------------------------------------------------------------
    # Aggregation helpers
    # ------------------------------------------------------------------

    def _aggregate_by_type(self) -> dict[str, list[Finding]]:
        """Group findings by type."""
        by_type: dict[str, list[Finding]] = defaultdict(list)
        for finding in self._findings:
            by_type[finding.type].append(finding)
        return dict(by_type)

    def _aggregate_by_severity(self) -> dict[str, list[Finding]]:
        """Group findings by severity (only findings with severity set)."""
        by_severity: dict[str, list[Finding]] = defaultdict(list)
        for finding in self._findings:
            if finding.severity:
                by_severity[finding.severity].append(finding)
        return dict(by_severity)

    def _summary_stats(self) -> dict[str, Any]:
        """Generate summary statistics."""
        by_type = self._aggregate_by_type()
        by_severity = self._aggregate_by_severity()

        total_duration = sum(
            r.duration_s for r in self._results_by_stage.values()
        )

        return {
            "total_findings": len(self._findings),
            "findings_by_type": {k: len(v) for k, v in by_type.items()},
            "findings_by_severity": {k: len(v) for k, v in by_severity.items()},
            "total_duration_s": round(total_duration, 2),
            "stages_completed": len(self._manifest.completed_stages()),
            "stages_failed": len(self._manifest.failed_stages()),
        }

    # ------------------------------------------------------------------
    # JSON export
    # ------------------------------------------------------------------

    def export_json(self, output_path: Path) -> None:
        """
        Export full structured report as JSON.

        Schema:
          {
            "metadata": {...},
            "summary": {...},
            "findings": [...],
            "stages": {...}
          }
        """
        report = {
            "metadata": {
                "target": self._manifest.target,
                "profile": self._manifest.profile,
                "workspace": self._manifest.workspace_path,
                "created_at": self._manifest.created_at,
                "updated_at": self._manifest.updated_at,
                "status": self._manifest.status,
                "tool_versions": self._manifest.tool_versions,
            },
            "summary": self._summary_stats(),
            "findings": [f.to_dict() for f in self._findings],
            "stages": {
                name: result.to_dict()
                for name, result in self._results_by_stage.items()
            },
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report, indent=2, default=str),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # Markdown export
    # ------------------------------------------------------------------

    def export_markdown(self, output_path: Path) -> None:
        """Export human-readable Markdown report."""
        template_path = Path(__file__).parent / "templates"
        env = Environment(
            loader=FileSystemLoader(str(template_path)),
            autoescape=select_autoescape(),
        )
        template = env.get_template("report.md.j2")

        by_type = self._aggregate_by_type()
        by_severity = self._aggregate_by_severity()
        summary = self._summary_stats()

        rendered = template.render(
            manifest=self._manifest,
            summary=summary,
            findings_by_type=by_type,
            findings_by_severity=by_severity,
            all_findings=self._findings,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")

    # ------------------------------------------------------------------
    # HTML export
    # ------------------------------------------------------------------

    def export_html(self, output_path: Path) -> None:
        """Export styled HTML report."""
        template_path = Path(__file__).parent / "templates"
        env = Environment(
            loader=FileSystemLoader(str(template_path)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("report.html.j2")

        by_type = self._aggregate_by_type()
        by_severity = self._aggregate_by_severity()
        summary = self._summary_stats()

        rendered = template.render(
            manifest=self._manifest,
            summary=summary,
            findings_by_type=by_type,
            findings_by_severity=by_severity,
            all_findings=self._findings,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")

    # ------------------------------------------------------------------
    # CSV export
    # ------------------------------------------------------------------

    def export_csv(self, output_path: Path) -> None:
        """
        Export findings as CSV (flat table).

        Columns: id, tool, type, target, value, severity, timestamp
        Metadata is JSON-serialized into a single column.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                "id", "tool", "type", "target", "value",
                "severity", "timestamp", "metadata",
            ])

            for finding in self._findings:
                writer.writerow([
                    finding.id,
                    finding.tool,
                    finding.type,
                    finding.target,
                    finding.value,
                    finding.severity or "",
                    finding.timestamp,
                    json.dumps(finding.metadata, default=str),
                ])


# ---------------------------------------------------------------------------
# Convenience function for CLI
# ---------------------------------------------------------------------------


def generate_report(
    workspace: Workspace,
    format_: str,
    output_path: Path | None = None,
) -> Path:
    """
    Generate a report in the specified format.

    Parameters
    ----------
    workspace:
        Workspace to report on.
    format_:
        One of: json, md, html, csv
    output_path:
        Explicit output path.  If None, defaults to
        workspace.reports_dir() / report.<format>

    Returns
    -------
    Path
        Path to the generated report file.
    """
    exporter = ReportExporter(workspace)

    if output_path is None:
        reports_dir = workspace.reports_dir()
        reports_dir.mkdir(parents=True, exist_ok=True)
        ext_map = {"json": "json", "md": "md", "html": "html", "csv": "csv"}
        output_path = reports_dir / f"report.{ext_map[format_]}"

    if format_ == "json":
        exporter.export_json(output_path)
    elif format_ == "md":
        exporter.export_markdown(output_path)
    elif format_ == "html":
        exporter.export_html(output_path)
    elif format_ == "csv":
        exporter.export_csv(output_path)
    else:
        raise ValueError(f"Unknown format: {format_}")

    return output_path
