from __future__ import annotations

import os
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .models import Finding, ToolRun


COPY_IGNORE = shutil.ignore_patterns(
    ".git", ".venv", "node_modules", "out", "cache", "broadcast", "reports", "__pycache__"
)


def _run(command: list[str], cwd: Path, timeout: int) -> ToolRun:
    name = Path(command[0]).name
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env={**os.environ, "NO_COLOR": "1"},
            check=False,
        )
        return ToolRun(
            name=name,
            status="passed" if result.returncode == 0 else "failed",
            command=command,
            exit_code=result.returncode,
            output=result.stdout[-20000:],
            duration_ms=round((time.perf_counter() - started) * 1000),
        )
    except subprocess.TimeoutExpired as exc:
        return ToolRun(
            name=name,
            status="timeout",
            command=command,
            output=(exc.stdout or "")[-20000:] if isinstance(exc.stdout, str) else "",
            note=f"Timed out after {timeout} seconds",
            duration_ms=round((time.perf_counter() - started) * 1000),
        )
    except OSError as exc:
        return ToolRun(name=name, status="unavailable", command=command, note=str(exc), duration_ms=round((time.perf_counter() - started) * 1000))


def _parse_slither(path: Path) -> list[dict[str, object]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    parsed: list[dict[str, object]] = []
    for detector in payload.get("results", {}).get("detectors", []):
        elements = detector.get("elements") or []
        mapping = elements[0].get("source_mapping", {}) if elements else {}
        lines = mapping.get("lines") or [0]
        parsed.append(
            {
                "rule_id": f"SLITHER-{detector.get('check', 'unknown')}",
                "severity": str(detector.get("impact", "Informational")).lower(),
                "confidence": str(detector.get("confidence", "Medium")).lower(),
                "title": str(detector.get("check", "Slither finding")).replace("-", " ").title(),
                "message": str(detector.get("description", "")).strip(),
                "path": mapping.get("filename_relative", ""),
                "line": int(lines[0]) if lines else 0,
            }
        )
    return parsed


def normalized_tool_findings(runs: list[ToolRun]) -> list[Finding]:
    severity_map = {
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "info",
        "optimization": "info",
    }
    findings: list[Finding] = []
    for run in runs:
        for item in run.parsed_findings:
            findings.append(
                Finding(
                    rule_id=str(item["rule_id"]),
                    severity=severity_map.get(str(item["severity"]), "info"),
                    title=str(item["title"]),
                    message=str(item["message"]),
                    path=str(item["path"]),
                    line=int(item["line"]),
                    confidence=str(item["confidence"]),
                    remediation="Confirm the Slither data flow and add a regression or invariant test before remediation.",
                    source="slither",
                    category="external-analysis",
                )
            )
    return findings


def run_isolated_tools(target: Path, fuzz_cases: int, timeout: int = 180) -> list[ToolRun]:
    project = target if target.is_dir() else target.parent
    runs: list[ToolRun] = []
    with tempfile.TemporaryDirectory(prefix="antiq-audit-") as temporary:
        copied = Path(temporary) / "project"
        shutil.copytree(project, copied, ignore=COPY_IGNORE)
        if (copied / "foundry.toml").exists() and shutil.which("forge"):
            runs.append(
                _run(
                    ["forge", "test", "--fuzz-runs", str(fuzz_cases)],
                    copied,
                    timeout,
                )
            )
        else:
            runs.append(
                ToolRun(
                    name="forge",
                    status="skipped",
                    note="No foundry.toml or forge executable; built-in policy fuzzing still ran.",
                )
            )

        if shutil.which("slither") and any(copied.rglob("*.sol")):
            slither_json = copied / "slither-results.json"
            slither = _run(["slither", ".", "--json", str(slither_json)], copied, timeout)
            slither.parsed_findings = _parse_slither(slither_json)
            if slither.parsed_findings:
                slither.status = "findings"
                slither.note = f"Slither reported {len(slither.parsed_findings)} normalized review findings."
            runs.append(slither)
        else:
            runs.append(
                ToolRun(name="slither", status="skipped", note="Slither or Solidity source unavailable.")
            )
    return runs
