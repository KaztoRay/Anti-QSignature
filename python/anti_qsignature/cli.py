from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .fuzzer import run_policy_fuzz
from .models import ScanReport
from .quantum import run_quantum_analysis
from .reporting import write_html, write_json
from .scanner import discover_files, fingerprint_bytecode, manifest_hash, scan_sources
from .tools import run_isolated_tools


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
        print(f"GUI 선택기를 열 수 없어 터미널 입력으로 전환합니다: {exc}", file=sys.stderr)
        return ""


def choose_target(raw: str | None, pick: str | None = None) -> Path:
    if raw:
        target = Path(raw).expanduser()
    else:
        entered = _gui_pick(pick) if pick else ""
        if not entered:
            entered = input("검사할 Solidity 파일 또는 프로젝트 디렉터리 경로: ").strip()
        target = Path(entered).expanduser()
    if not target.exists():
        raise FileNotFoundError(f"대상 경로를 찾을 수 없습니다: {target}")
    return target.resolve()


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="antiq", description="Q# 기반 스마트 컨트랙트 보안 검사")
    value.add_argument("target", nargs="?", help="Solidity 파일 또는 프로젝트 경로; 생략하면 대화형 선택")
    picker = value.add_mutually_exclusive_group()
    picker.add_argument("--pick-file", action="store_const", const="file", dest="pick", help="파일 선택 창 열기")
    picker.add_argument("--pick-dir", action="store_const", const="dir", dest="pick", help="프로젝트 폴더 선택 창 열기")
    value.add_argument("--fuzz-cases", type=int, default=512, help="내장/Foundry 퍼징 실행 수")
    value.add_argument("--seed", type=int, default=20261005, help="재현 가능한 내장 퍼징 시드")
    value.add_argument("--qsharp", choices=["auto", "off", "required"], default="auto")
    value.add_argument("--external-tools", action="store_true", help="격리 복사본에서 Forge와 Slither 실행")
    value.add_argument("--json", dest="json_path", default="reports/antiq-report.json")
    value.add_argument("--html", dest="html_path", default="reports/antiq-report.html")
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        target = choose_target(args.target, args.pick)
        root = target if target.is_dir() else target.parent
        files = discover_files(target)
        report = ScanReport(
            target=str(target),
            generated_at=datetime.now(timezone.utc).isoformat(),
            manifest_hash=manifest_hash(files, root),
            files_scanned=len(files),
        )
        report.findings = scan_sources(files, root)
        report.bytecode_fingerprints = fingerprint_bytecode(files, root)
        report.policy_fuzz = run_policy_fuzz(max(args.fuzz_cases, 1), args.seed)
        repository_root = Path(__file__).resolve().parents[2]
        report.quantum = run_quantum_analysis(repository_root, mode=args.qsharp)
        if args.external_tools:
            report.tools = run_isolated_tools(target, max(args.fuzz_cases, 1))
        report.sort_findings()
        json_output = Path(args.json_path).expanduser().resolve()
        html_output = Path(args.html_path).expanduser().resolve()
        write_json(report, json_output)
        write_html(report, html_output)
        print(json.dumps({
            "target": report.target,
            "files_scanned": report.files_scanned,
            "summary": report.summary(),
            "qsharp": report.quantum.get("qsharp_status"),
            "fuzz_failures": report.policy_fuzz.get("invariant_failures"),
            "json_report": str(json_output),
            "html_report": str(html_output),
        }, indent=2, ensure_ascii=False))
        return 2 if report.summary().get("critical", 0) else 0
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
