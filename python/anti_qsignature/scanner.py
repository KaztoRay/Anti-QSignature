from __future__ import annotations

import hashlib
import json
import fnmatch
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import Finding, relative_display


IGNORED_DIRS = {".git", ".venv", "node_modules", "cache", "broadcast", "reports", "venv"}
SOURCE_SUFFIXES = {".sol", ".vy", ".yul"}
MAX_FILE_BYTES = 8 * 1024 * 1024
EIP170_CODE_SIZE = 24_576


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
        re.compile(
            r"\bkeccak256\s*\(\s*abi\.encodePacked\s*\(\s*(password|pin|secret|seed)\b",
            re.IGNORECASE,
        ),
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
    Rule(
        "AQ011",
        re.compile(r"\b(blockhash|block\.prevrandao)\b"),
        "medium",
        "Block data used as entropy",
        "Block-derived values are predictable or influenceable and should not secure randomness-sensitive actions.",
        "Use a commit-reveal design or a verified randomness oracle.",
    ),
    Rule(
        "AQ012",
        re.compile(r"\bcallcode\s*\("),
        "critical",
        "Deprecated callcode",
        "callcode has delegatecall-like storage effects and should not be used.",
        "Remove callcode and redesign the execution boundary.",
        "high",
    ),
    Rule(
        "AQ013",
        re.compile(r"\bsstore\s*\("),
        "medium",
        "Raw storage write",
        "Assembly writes directly to storage and may violate layout or authorization invariants.",
        "Document the exact slot and add storage-layout and invariant tests.",
    ),
    Rule(
        "AQ014",
        re.compile(r"\.call\s*\([^;]*\)\s*;"),
        "medium",
        "Unchecked low-level call",
        "A low-level call result appears to be discarded.",
        "Capture and validate the success flag and returned data.",
    ),
]


def _excluded(path: Path, root: Path, patterns: Iterable[str]) -> bool:
    relative = relative_display(path, root)
    return any(fnmatch.fnmatch(relative, pattern) for pattern in patterns)


def discover_files(target: Path, exclude: Iterable[str] = ()) -> list[Path]:
    target = target.expanduser().resolve()
    root = target if target.is_dir() else target.parent
    if target.is_file():
        return [] if _excluded(target, root, exclude) else [target]
    files: list[Path] = []
    for current, dirs, names in os.walk(target):
        dirs[:] = [name for name in dirs if name not in IGNORED_DIRS]
        current_path = Path(current)
        for name in names:
            path = current_path / name
            if path.suffix.lower() not in SOURCE_SUFFIXES | {".json"} or _excluded(path, root, exclude):
                continue
            try:
                if path.stat().st_size <= MAX_FILE_BYTES:
                    files.append(path)
            except OSError:
                continue
    return sorted(files)


def _strip_comments_preserve_lines(text: str) -> list[str]:
    output: list[str] = []
    in_block = False
    for raw in text.splitlines():
        cleaned = ""
        index = 0
        while index < len(raw):
            if in_block:
                end = raw.find("*/", index)
                if end < 0:
                    index = len(raw)
                    continue
                in_block = False
                index = end + 2
                continue
            block = raw.find("/*", index)
            single = raw.find("//", index)
            if single >= 0 and (block < 0 or single < block):
                cleaned += raw[index:single]
                break
            if block >= 0:
                cleaned += raw[index:block]
                in_block = True
                index = block + 2
                continue
            cleaned += raw[index:]
            break
        output.append(cleaned)
    return output


def _scan_file(path: Path, root: Path) -> list[Finding]:
    if path.suffix.lower() not in SOURCE_SUFFIXES:
        return []
    try:
        raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    code_lines = _strip_comments_preserve_lines("\n".join(raw_lines))
    findings: list[Finding] = []
    for line_number, code in enumerate(code_lines, 1):
        for rule in RULES:
            if rule.pattern.search(code):
                findings.append(
                    Finding(
                        rule.rule_id,
                        rule.severity,
                        rule.title,
                        rule.message,
                        relative_display(path, root),
                        line_number,
                        raw_lines[line_number - 1].strip()[:300],
                        rule.confidence,
                        rule.remediation,
                    )
                )
    return findings


def scan_sources(files: Iterable[Path], root: Path, jobs: int | None = None) -> list[Finding]:
    sources = [path for path in files if path.suffix.lower() in SOURCE_SUFFIXES]
    workers = jobs or min(32, (os.cpu_count() or 2) + 4)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        batches = pool.map(lambda path: _scan_file(path, root), sources)
    return [finding for batch in batches for finding in batch]


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


def fingerprint_bytecode(files: Iterable[Path], root: Path) -> list[dict[str, object]]:
    fingerprints: list[dict[str, object]] = []
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
            if not normalized or not re.fullmatch(r"[0-9a-fA-F]+", normalized) or len(normalized) % 2:
                continue
            raw = bytes.fromhex(normalized)
            digest = hashlib.sha256(raw).hexdigest()
            identity = (str(path), digest)
            if identity in seen:
                continue
            seen.add(identity)
            fingerprints.append(
                {
                    "path": relative_display(path, root),
                    "location": location,
                    "sha256": digest,
                    "bytes": len(raw),
                    "eip170_limit_exceeded": "deployedBytecode" in location and len(raw) > EIP170_CODE_SIZE,
                }
            )
    return fingerprints


def bytecode_findings(fingerprints: Iterable[dict[str, object]]) -> list[Finding]:
    return [
        Finding(
            "AQ015",
            "high",
            "Deployed bytecode exceeds EIP-170 limit",
            f"Runtime bytecode is {item['bytes']} bytes; the EIP-170 limit is {EIP170_CODE_SIZE} bytes.",
            str(item["path"]),
            evidence=str(item["location"]),
            confidence="high",
            remediation="Split the contract, use libraries, or reduce generated runtime code.",
            source="antiq-bytecode",
            category="deployability",
        )
        for item in fingerprints
        if item.get("eip170_limit_exceeded")
    ]


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
