from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 compatibility
    import tomli as tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ProjectConfig:
    exclude: list[str] = field(default_factory=list)
    ignore_rules: list[str] = field(default_factory=list)
    fail_on: str = "high"
    fuzz_cases: int | None = None
    qsharp: str | None = None
    external_tools: bool | None = None


def load_project_config(path: Path | None) -> ProjectConfig:
    if path is None or not path.exists():
        return ProjectConfig()
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    scan = payload.get("scan", {})
    return ProjectConfig(
        exclude=[str(item) for item in scan.get("exclude", [])],
        ignore_rules=[str(item) for item in scan.get("ignore_rules", [])],
        fail_on=str(scan.get("fail_on", "high")),
        fuzz_cases=int(scan["fuzz_cases"]) if "fuzz_cases" in scan else None,
        qsharp=str(scan["qsharp"]) if "qsharp" in scan else None,
        external_tools=bool(scan["external_tools"]) if "external_tools" in scan else None,
    )
