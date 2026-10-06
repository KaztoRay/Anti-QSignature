from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from .config import load_project_config
from .fuzzer import run_policy_fuzz
from .models import SEVERITY_ORDER, ScanReport
from .quantum import run_quantum_analysis
from .reporting import write_html, write_json, write_markdown, write_sarif
from .scanner import bytecode_findings, discover_files, fingerprint_bytecode, manifest_hash, scan_sources
from .tools import normalized_tool_findings, run_isolated_tools


def _gui_pick(kind: str) -> str:
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        if kind == "file":
            selected = filedialog.askopenfilename(
                title="검사할 스마트 컨트랙트 선택",
                filetypes=[("Smart contracts", "*.sol *.vy *.yul"), ("All files", "*")],
            )
        else:
            selected = filedialog.askdirectory(title="검사할 컨트랙트 프로젝트 선택")
        root.destroy()
        return selected
    except Exception as exc:
        print(f"File picker unavailable; switching to terminal input: {exc}", file=sys.stderr)
        return ""


def choose_target(raw: str | None, pick: str | None = None) -> Path:
    if raw:
        target = Path(raw).expanduser()
    else:
        entered = _gui_pick(pick) if pick else ""
        if not entered:
            entered = input("Solidity file or project directory to scan: ").strip()
        if not entered:
            raise ValueError("A scan target is required.")
        target = Path(entered).expanduser()
    if not target.exists():
        raise FileNotFoundError(f"Scan target does not exist: {target}")
    if not target.is_file() and not target.is_dir():
        raise ValueError(f"Scan target must be a file or directory: {target}")
    if target.is_file() and target.suffix.lower() not in {".sol", ".vy", ".yul", ".json"}:
        raise ValueError(f"Unsupported scan target file: {target}")
    return target.resolve()


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="antiq", description="Anti-Quantum smart contract security scanner")
    value.add_argument("target", nargs="?", help="Solidity file or project path; prompts if omitted")
    picker = value.add_mutually_exclusive_group()
    picker.add_argument("--pick-file", action="store_const", const="file", dest="pick", help="Open file picker")
    picker.add_argument("--pick-dir", action="store_const", const="dir", dest="pick", help="Open directory picker")
    value.add_argument("--config", help="Path to .antiq.toml; defaults to the target project root")
    value.add_argument("--fuzz-cases", type=int, help="Built-in and Foundry fuzz case count")
    value.add_argument("--seed", type=int, default=20261005, help="Reproducible built-in fuzz seed")
    value.add_argument("--qsharp", choices=["auto", "off", "required"])
    value.add_argument(
        "--external-tools",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Run Forge and Slither on an isolated copy",
    )
    value.add_argument("--jobs", type=int, default=0, help="Parallel scan workers; 0 selects automatically")
    value.add_argument("--exclude", action="append", default=[], help="Glob pattern to exclude; repeatable")
    value.add_argument("--ignore-rule", action="append", default=[], help="Accepted rule ID; repeatable")
    value.add_argument("--baseline", help="Previous JSON report for new and resolved finding comparison")
    value.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="CI failure severity threshold")
    value.add_argument("--json", dest="json_path", default="reports/antiq-report.json")
    value.add_argument("--html", dest="html_path", default="reports/antiq-report.html")
    value.add_argument("--sarif", dest="sarif_path", default="reports/antiq-report.sarif")
    value.add_argument("--markdown", dest="markdown_path", default="reports/antiq-report.md")
    return value


def apply_baseline(report: ScanReport, path: str | None) -> None:
    if not path:
        report.baseline = {"new": len(report.findings), "unchanged": 0, "resolved": 0}
        report.findings = [replace(item, status="new") for item in report.findings]
        return
    baseline_path = Path(path).expanduser().resolve()
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    previous = {str(item.get("fingerprint")) for item in payload.get("findings", []) if item.get("fingerprint")}
    current = {item.fingerprint for item in report.findings}
    report.findings = [replace(item, status="existing" if item.fingerprint in previous else "new") for item in report.findings]
    report.baseline = {
        "path": str(baseline_path),
        "new": len(current - previous),
        "unchanged": len(current & previous),
        "resolved": len(previous - current),
    }


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        total_started = time.perf_counter()
        target = choose_target(args.target, args.pick)
        root = target if target.is_dir() else target.parent
        config_path = Path(args.config).expanduser().resolve() if args.config else root / ".antiq.toml"
        config = load_project_config(config_path)
        exclusions = [*config.exclude, *args.exclude]
        ignored_rules = set(config.ignore_rules) | set(args.ignore_rule)
        fuzz_cases = args.fuzz_cases if args.fuzz_cases is not None else (config.fuzz_cases or 512)
        if fuzz_cases < 1:
            raise ValueError("fuzz_cases must be at least 1")
        if args.jobs < 0:
            raise ValueError("jobs must be 0 or greater")
        if args.seed < 0:
            raise ValueError("seed must be 0 or greater")
        qsharp_mode = args.qsharp or config.qsharp or "auto"
        if qsharp_mode not in {"auto", "off", "required"}:
            raise ValueError(f"Invalid qsharp mode in {config_path}: {qsharp_mode}")
        external_tools = args.external_tools if args.external_tools is not None else bool(config.external_tools)
        fail_on = args.fail_on or config.fail_on
        if fail_on not in SEVERITY_ORDER:
            raise ValueError(f"Invalid fail_on severity in {config_path}: {fail_on}")
        phase = time.perf_counter()
        files = discover_files(target, exclusions)
        report = ScanReport(
            target=str(target),
            generated_at=datetime.now(timezone.utc).isoformat(),
            manifest_hash=manifest_hash(files, root),
            files_scanned=len(files),
        )
        report.metrics["discovery_ms"] = round((time.perf_counter() - phase) * 1000)
        report.metrics["source_files"] = sum(path.suffix.lower() in {".sol", ".vy", ".yul"} for path in files)
        report.metrics["artifact_files"] = sum(path.suffix.lower() == ".json" for path in files)
        phase = time.perf_counter()
        report.findings = scan_sources(files, root, args.jobs or None)
        report.metrics["static_scan_ms"] = round((time.perf_counter() - phase) * 1000)
        phase = time.perf_counter()
        report.bytecode_fingerprints = fingerprint_bytecode(files, root, args.jobs or None)
        report.findings.extend(bytecode_findings(report.bytecode_fingerprints))
        before_suppression = len(report.findings)
        report.findings = [item for item in report.findings if item.rule_id not in ignored_rules]
        report.metrics["suppressed_findings"] = before_suppression - len(report.findings)
        report.metrics["config_path"] = str(config_path) if config_path.exists() else None
        report.metrics["bytecode_ms"] = round((time.perf_counter() - phase) * 1000)
        phase = time.perf_counter()
        report.policy_fuzz = run_policy_fuzz(fuzz_cases, args.seed)
        report.metrics["policy_fuzz_ms"] = round((time.perf_counter() - phase) * 1000)
        repository_root = Path(__file__).resolve().parents[2]
        phase = time.perf_counter()
        report.quantum = run_quantum_analysis(
            repository_root,
            mode=qsharp_mode,
            finding_rule_ids={item.rule_id for item in report.findings},
        )
        report.metrics["qsharp_ms"] = round((time.perf_counter() - phase) * 1000)
        if external_tools:
            report.tools = run_isolated_tools(target, fuzz_cases)
            report.findings.extend(normalized_tool_findings(report.tools))
            before_external_suppression = len(report.findings)
            report.findings = [item for item in report.findings if item.rule_id not in ignored_rules]
            report.metrics["suppressed_findings"] += before_external_suppression - len(report.findings)
        apply_baseline(report, args.baseline)
        report.sort_findings()
        report.metrics["duration_ms"] = round((time.perf_counter() - total_started) * 1000)
        json_output = Path(args.json_path).expanduser().resolve()
        html_output = Path(args.html_path).expanduser().resolve()
        sarif_output = Path(args.sarif_path).expanduser().resolve()
        markdown_output = Path(args.markdown_path).expanduser().resolve()
        write_json(report, json_output)
        write_html(report, html_output)
        write_sarif(report, sarif_output)
        write_markdown(report, markdown_output)
        print(json.dumps({
            "target": report.target,
            "files_scanned": report.files_scanned,
            "summary": report.summary(),
            "qsharp": report.quantum.get("qsharp_status"),
            "fuzz_failures": report.policy_fuzz.get("invariant_failures"),
            "risk_score": report.risk_score(),
            "verdict": report.verdict(),
            "baseline": report.baseline,
            "duration_ms": report.metrics.get("duration_ms"),
            "json_report": str(json_output),
            "html_report": str(html_output),
            "sarif_report": str(sarif_output),
            "markdown_report": str(markdown_output),
        }, indent=2, ensure_ascii=False))
        threshold = SEVERITY_ORDER[fail_on]
        should_fail = any(SEVERITY_ORDER.get(item.severity, 99) <= threshold for item in report.findings)
        return 2 if should_fail else 0
    except (FileNotFoundError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
