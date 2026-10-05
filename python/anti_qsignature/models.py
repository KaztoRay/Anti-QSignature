from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    path: str
    line: int = 0
    evidence: str = ""
    confidence: str = "medium"
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolRun:
    name: str
    status: str
    command: list[str] = field(default_factory=list)
    exit_code: int | None = None
    output: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    target: str
    generated_at: str
    manifest_hash: str
    files_scanned: int
    findings: list[Finding] = field(default_factory=list)
    bytecode_fingerprints: list[dict[str, str]] = field(default_factory=list)
    policy_fuzz: dict[str, Any] = field(default_factory=dict)
    quantum: dict[str, Any] = field(default_factory=dict)
    tools: list[ToolRun] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["summary"] = self.summary()
        return data

    def summary(self) -> dict[str, int]:
        result = {key: 0 for key in SEVERITY_ORDER}
        for finding in self.findings:
            result[finding.severity] = result.get(finding.severity, 0) + 1
        return result

    def sort_findings(self) -> None:
        self.findings.sort(
            key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.path, item.line)
        )


def relative_display(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)

