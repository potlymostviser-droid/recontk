"""
recontk.models
~~~~~~~~~~~~~~
Canonical data model shared across all phases.

All tool wrappers, native backends, and modules MUST return NormalizedResult.
Severity values MUST come from the upstream tool; never invented here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _make_finding_id(tool: str, type_: str, target: str, value: str) -> str:
    """
    Deterministic SHA-256-based identifier for a Finding.

    The ID is derived from (tool, type, target, value) so that the same
    logical finding produced by two separate runs produces the same ID,
    enabling deduplication in reports.
    """
    raw = f"{tool}\x00{type_}\x00{target}\x00{value}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """
    A single discrete observation produced by a tool or native backend.

    Attributes
    ----------
    id:
        Deterministic 16-hex-char hash of (tool, type, target, value).
    tool:
        Tool or native backend that produced this finding.
    type:
        Capability-scoped type string, e.g.:
          "open-port", "subdomain", "vuln", "tls-issue",
          "http-header", "screenshot", "whois-record", "dns-record"
    target:
        The scan target (host, IP, URL) this finding relates to.
    value:
        The finding's primary value (port number, FQDN, CVE ID, etc.).
    severity:
        Only populated when the upstream tool provides it (e.g. nuclei).
        Never invented. Valid upstream values: info, low, medium, high,
        critical — but we do not validate or constrain this.
    metadata:
        Tool-specific structured extras (raw JSON-serialisable dict).
    timestamp:
        ISO8601 UTC timestamp of when the finding was recorded.
    """

    tool: str
    type: str
    target: str
    value: str
    severity: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=_now_iso)
    id: str = field(init=False)

    def __post_init__(self) -> None:
        self.id = _make_finding_id(self.tool, self.type, self.target, self.value)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "type": self.type,
            "target": self.target,
            "value": self.value,
            "severity": self.severity,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        obj = cls(
            tool=data["tool"],
            type=data["type"],
            target=data["target"],
            value=data["value"],
            severity=data.get("severity"),
            metadata=data.get("metadata", {}),
            timestamp=data.get("timestamp", _now_iso()),
        )
        # Overwrite auto-generated id with stored id for round-trip fidelity
        stored_id = data.get("id")
        if stored_id:
            object.__setattr__(obj, "id", stored_id)
        return obj

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


# ---------------------------------------------------------------------------
# NormalizedResult
# ---------------------------------------------------------------------------


@dataclass
class NormalizedResult:
    """
    The standard return type for every tool wrapper and native backend.

    Attributes
    ----------
    tool:
        Name of the tool or native backend (matches registry key).
    target:
        The scan target.
    duration_s:
        Wall-clock seconds the tool ran for.
    findings:
        Zero or more Finding instances.
    errors:
        Human-readable error strings (non-fatal issues logged here;
        fatal errors raise exceptions instead).
    raw_path:
        Absolute path to the untouched tool output file, or None if the
        tool produced no output file (e.g. native backends that work
        entirely in memory).
    """

    tool: str
    target: str
    duration_s: float
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    raw_path: str | None = None

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0

    def findings_by_type(self, type_: str) -> list[Finding]:
        return [f for f in self.findings if f.type == type_]

    def findings_by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def merge(self, other: "NormalizedResult") -> "NormalizedResult":
        """
        Merge another NormalizedResult into this one (in-place).
        Used when multiple tools satisfy the same capability and their
        results are combined.
        """
        seen_ids = {f.id for f in self.findings}
        for finding in other.findings:
            if finding.id not in seen_ids:
                self.findings.append(finding)
                seen_ids.add(finding.id)
        self.errors.extend(other.errors)
        self.duration_s += other.duration_s
        return self

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "target": self.target,
            "duration_s": self.duration_s,
            "finding_count": self.finding_count,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "raw_path": self.raw_path,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NormalizedResult":
        findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        return cls(
            tool=data["tool"],
            target=data["target"],
            duration_s=float(data.get("duration_s", 0.0)),
            findings=findings,
            errors=data.get("errors", []),
            raw_path=data.get("raw_path"),
        )

    @classmethod
    def from_json(cls, text: str) -> "NormalizedResult":
        return cls.from_dict(json.loads(text))

    def save(self, path: "Any") -> None:
        """Write this result as indented JSON to ``path``."""
        from pathlib import Path as _Path

        p = _Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, path: "Any") -> "NormalizedResult":
        from pathlib import Path as _Path

        return cls.from_json(_Path(path).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Unit-test stubs
# ---------------------------------------------------------------------------


def _test_finding_id_determinism() -> None:
    """Same (tool, type, target, value) → same id."""
    f1 = Finding(tool="nmap", type="open-port", target="10.0.0.1", value="80/tcp")
    f2 = Finding(tool="nmap", type="open-port", target="10.0.0.1", value="80/tcp")
    assert f1.id == f2.id, f"IDs differ: {f1.id} vs {f2.id}"
    print("models._test_finding_id_determinism PASSED")


def _test_finding_id_uniqueness() -> None:
    """Different value → different id."""
    f1 = Finding(tool="nmap", type="open-port", target="10.0.0.1", value="80/tcp")
    f2 = Finding(tool="nmap", type="open-port", target="10.0.0.1", value="443/tcp")
    assert f1.id != f2.id
    print("models._test_finding_id_uniqueness PASSED")


def _test_normalized_result_round_trip() -> None:
    """NormalizedResult serialises and deserialises cleanly."""
    result = NormalizedResult(
        tool="nmap",
        target="10.0.0.1",
        duration_s=12.34,
        findings=[
            Finding(
                tool="nmap",
                type="open-port",
                target="10.0.0.1",
                value="22/tcp",
                metadata={"service": "ssh", "version": "OpenSSH 9.0"},
            )
        ],
        errors=[],
        raw_path="/tmp/raw/nmap/output.xml",
    )
    restored = NormalizedResult.from_json(result.to_json())
    assert restored.tool == "nmap"
    assert restored.target == "10.0.0.1"
    assert len(restored.findings) == 1
    assert restored.findings[0].id == result.findings[0].id
    assert restored.findings[0].metadata["service"] == "ssh"
    print("models._test_normalized_result_round_trip PASSED")


def _test_merge_deduplication() -> None:
    """merge() does not duplicate findings with the same id."""
    f = Finding(tool="nmap", type="open-port", target="10.0.0.1", value="80/tcp")
    r1 = NormalizedResult(tool="nmap", target="10.0.0.1", duration_s=1.0, findings=[f])
    r2 = NormalizedResult(tool="nmap", target="10.0.0.1", duration_s=2.0, findings=[f])
    r1.merge(r2)
    assert len(r1.findings) == 1, f"Expected 1 finding after merge, got {len(r1.findings)}"
    assert r1.duration_s == 3.0
    print("models._test_merge_deduplication PASSED")


if __name__ == "__main__":
    _test_finding_id_determinism()
    _test_finding_id_uniqueness()
    _test_normalized_result_round_trip()
    _test_merge_deduplication()
