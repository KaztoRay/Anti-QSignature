from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .models import ToolRun


COPY_IGNORE = shutil.ignore_patterns(
    ".git", ".venv", "node_modules", "out", "cache", "broadcast", "reports", "__pycache__"
)


def _run(command: list[str], cwd: Path, timeout: int) -> ToolRun:
    name = Path(command[0]).name
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
        )
    except subprocess.TimeoutExpired as exc:
        return ToolRun(
            name=name,
            status="timeout",
            command=command,
            output=(exc.stdout or "")[-20000:] if isinstance(exc.stdout, str) else "",
            note=f"Timed out after {timeout} seconds",
        )
    except OSError as exc:
        return ToolRun(name=name, status="unavailable", command=command, note=str(exc))


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
            slither = _run(["slither", ".", "--json", "-"], copied, timeout)
            if slither.exit_code == 255 and '"success": true' in slither.output:
                slither.status = "findings"
                slither.note = "Slither completed and reported one or more review findings."
            runs.append(slither)
        else:
            runs.append(
                ToolRun(name="slither", status="skipped", note="Slither or Solidity source unavailable.")
            )
    return runs
