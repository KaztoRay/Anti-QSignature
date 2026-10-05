from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}


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
    source: str = "antiq"
    category: str = "smart-contract"
    status: str = "current"

    @property
    def fingerprint(self) -> str:
        stable = f"{self.source}|{self.rule_id}|{self.path}|{self.line}|{self.evidence.strip()}"
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()[:20]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["fingerprint"] = self.fingerprint
        return data


@dataclass
class ToolRun:
    name: str
    status: str
    command: list[str] = field(default_factory=list)
    exit_code: int | None = None
    output: str = ""
    note: str = ""
    duration_ms: int = 0
    parsed_findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    target: str
    generated_at: str
    manifest_hash: str
    files_scanned: int
    findings: list[Finding] = field(default_factory=list)
    bytecode_fingerprints: list[dict[str, Any]] = field(default_factory=list)
    policy_fuzz: dict[str, Any] = field(default_factory=dict)
    quantum: dict[str, Any] = field(default_factory=dict)
    tools: list[ToolRun] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    baseline: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [item.to_dict() for item in self.findings]
        data["summary"] = self.summary()
        data["risk_score"] = self.risk_score()
        data["verdict"] = self.verdict()
        return data

    def summary(self) -> dict[str, int]:
        result = {key: 0 for key in SEVERITY_ORDER}
        for finding in self.findings:
            result[finding.severity] = result.get(finding.severity, 0) + 1
        return result

    def risk_score(self) -> int:
        raw = sum(SEVERITY_WEIGHT.get(item.severity, 0) for item in self.findings)
        return min(100, raw)

    def verdict(self) -> str:
        summary = self.summary()
        if summary["critical"]:
            return "BLOCK"
        if summary["high"]:
            return "REVIEW_REQUIRED"
        if summary["medium"]:
            return "CAUTION"
        return "PASS_WITH_NOTES"

    def sort_findings(self) -> None:
        self.findings.sort(
            key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.path, item.line, item.rule_id)
        )


def relative_display(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
