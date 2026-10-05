from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import Finding, relative_display


IGNORED_DIRS = {".git", ".venv", "node_modules", "cache", "broadcast", "reports", "venv"}
SOURCE_SUFFIXES = {".sol", ".vy", ".yul"}
MAX_FILE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class Rule:
    rule_id: str
    pattern: re.Pattern[str]
    severity: str
    title: str
    message: str
    remediation: str
    confidence: str = "medium"


RULES = [
    Rule(
        "AQ001",
        re.compile(r"\btx\.origin\b"),
        "high",
        "tx.origin authorization",
        "tx.origin based authorization can be bypassed through an intermediate contract.",
        "Use msg.sender with explicit roles or signature-based authorization.",
        "high",
    ),
    Rule(
        "AQ002",
        re.compile(r"\.delegatecall\s*\("),
        "high",
        "Delegatecall surface",
        "delegatecall executes foreign code in the caller's storage context.",
        "Restrict implementation addresses and verify runtime code hashes in an immutable guard.",
    ),
    Rule(
        "AQ003",
        re.compile(r"\bselfdestruct\s*\("),
        "high",
        "Destructive opcode",
        "The contract exposes a selfdestruct code path.",
        "Remove selfdestruct and use an explicit pause or migration mechanism.",
        "high",
    ),
    Rule(
        "AQ004",
        re.compile(r"\.call\s*\{[^}]*value\s*:"),
        "medium",
        "External value call",
        "An external value transfer may permit reentrancy when state is updated afterward.",
        "Apply checks-effects-interactions and a reentrancy guard; fuzz the state invariant.",
    ),
    Rule(
        "AQ005",
        re.compile(r"\bblock\.timestamp\b|\bnow\b"),
        "low",
        "Timestamp dependence",
        "Block timestamp influences contract behavior and has limited proposer flexibility.",
        "Use timestamps only with an adequate tolerance; avoid them as entropy.",
    ),
    Rule(
        "AQ006",
        re.compile(r"\bassembly\s*\{"),
        "medium",
        "Inline assembly",
        "Inline assembly bypasses several Solidity safety checks and needs manual review.",
        "Keep the assembly block minimal and add property/invariant tests for its effects.",
    ),
    Rule(
        "AQ007",
        re.compile(r"\becrecover\s*\("),
        "medium",
        "Raw ECDSA recovery",
        "Raw ecrecover usage requires explicit malleability, zero-address, domain, and replay checks.",
        "Validate low-s/v, bind chainId and contract address, and include a monotonic nonce.",
    ),
    Rule(
        "AQ008",
        re.compile(r"\bkeccak256\s*\([^)]*(password|secret|pin|seed)" , re.IGNORECASE),
        "high",
        "Low-entropy secret commitment",
        "A public hash of a human-scale secret can be searched offline and gains a Grover speedup.",
        "Do not keep secrets on-chain; use high-entropy keys and domain-separated commitments.",
    ),
    Rule(
        "AQ009",
        re.compile(r"\bupgradeTo(?:AndCall)?\s*\("),
        "medium",
        "Upgradeable implementation",
        "An upgrade entry point was detected; authorization and code integrity are critical.",
        "Require a timelock, PQ-capable authorization, approved code hash, and code epoch bump.",
    ),
    Rule(
        "AQ010",
        re.compile(r"\babi\.encodePacked\s*\("),
        "low",
        "Packed encoding",
        "Packed encoding can be ambiguous when multiple dynamic values are concatenated.",
        "Prefer abi.encode for signatures and commitments unless all boundaries are fixed.",
    ),
]


def discover_files(target: Path) -> list[Path]:
    target = target.expanduser().resolve()
    if target.is_file():
        return [target]
    files: list[Path] = []
    for path in target.rglob("*"):
        if not path.is_file() or any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SOURCE_SUFFIXES or path.suffix.lower() == ".json":
            try:
                if path.stat().st_size <= MAX_FILE_BYTES:
                    files.append(path)
            except OSError:
                continue
    return sorted(files)


def scan_sources(files: Iterable[Path], root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in files:
        if path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_number, line in enumerate(lines, 1):
            code = line.split("//", 1)[0]
            for rule in RULES:
                match = rule.pattern.search(code)
                if match:
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            title=rule.title,
                            message=rule.message,
                            path=relative_display(path, root),
                            line=line_number,
                            evidence=line.strip()[:240],
                            confidence=rule.confidence,
                            remediation=rule.remediation,
                        )
                    )
    return findings


def _bytecode_values(node: object, prefix: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(node, dict):
        for key, value in node.items():
            label = f"{prefix}.{key}" if prefix else key
            if key in {"bytecode", "deployedBytecode"}:
                if isinstance(value, str):
                    yield label, value
                elif isinstance(value, dict) and isinstance(value.get("object"), str):
                    yield f"{label}.object", value["object"]
            yield from _bytecode_values(value, label)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _bytecode_values(value, f"{prefix}[{index}]")


def fingerprint_bytecode(files: Iterable[Path], root: Path) -> list[dict[str, str]]:
    fingerprints: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for path in files:
        if path.suffix.lower() != ".json":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for location, value in _bytecode_values(data):
            normalized = value.removeprefix("0x")
            if not normalized or not re.fullmatch(r"[0-9a-fA-F]+", normalized):
                continue
            digest = hashlib.sha256(bytes.fromhex(normalized)).hexdigest()
            identity = (str(path), digest)
            if identity in seen:
                continue
            seen.add(identity)
            fingerprints.append(
                {
                    "path": relative_display(path, root),
                    "location": location,
                    "sha256": digest,
                    "bytes": str(len(normalized) // 2),
                }
            )
    return fingerprints


def manifest_hash(files: Iterable[Path], root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(files):
        try:
            content = path.read_bytes()
        except OSError:
            continue
        digest.update(relative_display(path, root).encode())
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()
