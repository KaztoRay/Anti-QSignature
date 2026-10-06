from __future__ import annotations

import html
import json
from pathlib import Path

from .models import ScanReport


def write_json(report: ScanReport, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")


def write_sarif(report: ScanReport, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    security_score = {"critical": "9.8", "high": "8.0", "medium": "5.5", "low": "2.5", "info": "0.0"}
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for item in report.findings:
        rules[item.rule_id] = {
            "id": item.rule_id,
            "name": item.title,
            "shortDescription": {"text": item.message},
            "help": {"text": item.remediation},
            "properties": {"security-severity": security_score.get(item.severity, "0.0"), "source": item.source, "tags": ["security", item.category]},
        }
        results.append(
            {
                "ruleId": item.rule_id,
                "level": level.get(item.severity, "note"),
                "message": {"text": item.message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.path}, "region": {"startLine": max(item.line, 1)}}}],
                "partialFingerprints": {"antiqFingerprint": item.fingerprint},
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Anti-Quantum", "version": "0.2.0", "rules": list(rules.values())}}, "results": results}],
    }
    output.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")


def write_markdown(report: ScanReport, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    summary = report.summary()
    lines = [
        "# Anti-Quantum Security Report",
        "",
        f"- **Verdict:** `{report.verdict()}`",
        f"- **Risk score:** `{report.risk_score()}/100`",
        f"- **Target:** `{report.target}`",
        f"- **Manifest:** `{report.manifest_hash}`",
        f"- **Findings:** critical {summary['critical']}, high {summary['high']}, medium {summary['medium']}, low {summary['low']}, info {summary['info']}",
        "",
        "## Findings",
        "",
        "| Severity | Rule | Location | Finding |",
        "|---|---|---|---|",
    ]
    for item in report.findings:
        message = item.message.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {item.severity.upper()} | {item.rule_id} | `{item.path}:{item.line}` | {message} |")
    lines.extend(["", "## Q# verification", "", "```json", json.dumps(report.quantum, indent=2, ensure_ascii=False), "```", ""])
    output.write_text("\n".join(lines), encoding="utf-8")


def _finding_html(item: object) -> str:
    severity = html.escape(item.severity)
    searchable = html.escape(f"{item.rule_id} {item.title} {item.path} {item.message} {item.source}".lower())
    return f"""
    <article class="finding" data-severity="{severity}" data-search="{searchable}">
      <div class="finding-head"><span class="badge {severity}">{severity.upper()}</span><span class="source">{html.escape(item.source)}</span><code>{html.escape(item.rule_id)}</code></div>
      <h3>{html.escape(item.title)}</h3>
      <div class="location">{html.escape(item.path)}:{item.line}</div>
      <p>{html.escape(item.message)}</p>
      {f'<pre><code>{html.escape(item.evidence)}</code></pre>' if item.evidence else ''}
      <div class="remediation"><strong>조치:</strong> {html.escape(item.remediation)}</div>
      <small>신뢰도 {html.escape(item.confidence)} · fingerprint {item.fingerprint}</small>
    </article>"""


def write_html(report: ScanReport, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    summary = report.summary()
    qh = report.quantum.get("policy_invariant_harness", {})
    uh = report.quantum.get("upgrade_invariant_harness", {})
    dh = report.quantum.get("signature_domain_harness", {})
    crh = report.quantum.get("contract_risk_harness", {})
    tsh = report.quantum.get("transaction_sequence_harness", {})
    aah = report.quantum.get("account_abstraction_harness", {})
    krh = report.quantum.get("key_rotation_harness", {})
    grh = report.quantum.get("guardian_recovery_harness", {})
    gh = report.quantum.get("grover_attack_harness", {})
    drg = report.quantum.get("dynamic_risk_grover_harness", {})
    cards = "".join(
        f'<button class="metric sev-{key}" onclick="filterSeverity(\'{key}\')"><span>{key.upper()}</span><strong>{value}</strong></button>'
        for key, value in summary.items()
    )
    findings = "".join(_finding_html(item) for item in report.findings) or '<div class="empty">표시할 취약점 후보가 없습니다.</div>'
    tools = "".join(
        f'<details><summary><b>{html.escape(tool.name)}</b><span class="tool-status {html.escape(tool.status)}">{html.escape(tool.status)}</span><span>{tool.duration_ms} ms</span></summary><p>{html.escape(tool.note)}</p><pre>{html.escape(tool.output[-8000:])}</pre></details>'
        for tool in report.tools
    ) or '<div class="empty">외부 도구를 실행하지 않았습니다.</div>'
    estimates = "".join(
        f"<tr><td>{row.get('register_qubits')}</td><td>{row.get('algorithmic_logical_qubits')}</td><td>{row.get('algorithmic_logical_depth')}</td><td>{row.get('physical_qubits')}</td><td>{row.get('runtime')}</td></tr>"
        for row in report.quantum.get("attack_round_resource_estimates", [])
    )
    baseline = report.baseline or {"new": 0, "unchanged": len(report.findings), "resolved": 0}
    document = f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Anti-Quantum · {html.escape(report.verdict())}</title>
<style>
:root{{--bg:#08111f;--panel:#101c2e;--panel2:#15243a;--text:#e8eef9;--muted:#91a2bc;--line:#263a55;--accent:#55d6be;--critical:#ff4d6d;--high:#ff7b54;--medium:#f7c948;--low:#60a5fa;--info:#94a3b8}}*{{box-sizing:border-box}}body{{margin:0;background:linear-gradient(145deg,#07101d,#0d1930);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui}}.wrap{{max-width:1280px;margin:auto;padding:36px 24px 72px}}header{{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;margin-bottom:24px}}h1{{font-size:30px;margin:0 0 6px}}h2{{margin:34px 0 14px;font-size:19px}}h3{{margin:9px 0 3px;font-size:16px}}p{{margin:8px 0}}code{{font-family:ui-monospace,SFMono-Regular,monospace}}.muted,.location,small{{color:var(--muted)}}.verdict{{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:18px 22px;min-width:220px}}.verdict strong{{display:block;font-size:25px;color:var(--accent)}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:10px}}.metric{{text-align:left;color:var(--text);background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:14px;cursor:pointer}}.metric span{{display:block;font-size:11px;color:var(--muted)}}.metric strong{{font-size:25px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}}.panel{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:17px}}.panel b{{display:block;font-size:21px;color:var(--accent)}}.toolbar{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;position:sticky;top:0;background:#0b1628e8;padding:12px 0;backdrop-filter:blur(8px);z-index:2}}input,select{{background:var(--panel2);border:1px solid var(--line);border-radius:9px;color:var(--text);padding:10px 12px}}input{{flex:1;min-width:220px}}.finding{{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:12px;padding:16px;margin:10px 0}}.finding[data-severity=critical]{{border-left-color:var(--critical)}}.finding[data-severity=high]{{border-left-color:var(--high)}}.finding[data-severity=medium]{{border-left-color:var(--medium)}}.finding[data-severity=low]{{border-left-color:var(--low)}}.finding-head{{display:flex;align-items:center;gap:9px}}.badge,.source,.tool-status{{border-radius:999px;padding:2px 8px;font-size:11px;background:#263a55}}.badge.critical{{background:var(--critical)}}.badge.high{{background:var(--high)}}.badge.medium{{background:#806710}}.badge.low{{background:#175ba4}}pre{{white-space:pre-wrap;word-break:break-word;background:#07101d;border:1px solid var(--line);padding:11px;border-radius:8px;max-height:360px;overflow:auto}}.remediation{{background:#112d32;border-radius:8px;padding:10px;margin:10px 0}}table{{border-collapse:collapse;width:100%}}th,td{{padding:9px;border-bottom:1px solid var(--line);text-align:left}}details{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px;margin:8px 0}}summary{{display:flex;gap:14px;cursor:pointer}}.empty{{padding:28px;text-align:center;border:1px dashed var(--line);color:var(--muted);border-radius:12px}}@media(max-width:700px){{header{{display:block}}.verdict{{margin-top:16px}}}}
</style></head><body><main class="wrap">
<header><div><h1>Anti-Quantum 보안 보고서</h1><div class="muted">{html.escape(report.target)}</div><div class="muted">생성 {html.escape(report.generated_at)} · {report.files_scanned}개 파일 · {report.metrics.get('duration_ms','-')} ms</div></div><div class="verdict"><span>배포 판단</span><strong>{report.verdict()}</strong><span>Risk {report.risk_score()}/100</span></div></header>
<section class="metrics">{cards}</section>
<h2>실행 요약</h2><section class="grid"><div class="panel">신규 발견<b>{baseline.get('new',0)}</b></div><div class="panel">해결됨<b>{baseline.get('resolved',0)}</b></div><div class="panel">Q# 검증 상태<b>{html.escape(str(report.quantum.get('qsharp_status','unknown')))}</b></div><div class="panel">정책 퍼징 반례<b>{report.policy_fuzz.get('invariant_failures',0)}</b></div></section>
<h2>Q# 정책 검증 하네스</h2><section class="grid"><div class="panel">전체 상태 검사<b>{report.quantum.get('total_qsharp_states_verified','-')}</b><span>Q# exhaustive verification</span></div><div class="panel">지갑 정책 반례<b>{qh.get('hardened_violations','-')}</b><span>Mutant detected: {qh.get('mutant_violations_detected','-')}</span></div><div class="panel">업그레이드 반례<b>{uh.get('hardened_violations','-')}</b><span>Mutant detected: {uh.get('mutant_violations_detected','-')}</span></div><div class="panel">서명 도메인 반례<b>{dh.get('hardened_violations','-')}</b><span>Mutant detected: {dh.get('mutant_violations_detected','-')}</span></div><div class="panel">트랜잭션 순서 반례<b>{tsh.get('hardened_violations','-')}</b><span>{tsh.get('sequences_checked','-')} sequences · mutant {tsh.get('mutant_violations_detected','-')}</span></div><div class="panel">ERC-4337 반례<b>{aah.get('hardened_violations','-')}</b><span>{aah.get('states_checked','-')} states · mutant {aah.get('mutant_violations_detected','-')}</span></div><div class="panel">PQ 키 회전 반례<b>{krh.get('hardened_violations','-')}</b><span>{krh.get('states_checked','-')} states · mutant {krh.get('mutant_violations_detected','-')}</span></div><div class="panel">가디언 복구 반례<b>{grh.get('hardened_violations','-')}</b><span>{grh.get('states_checked','-')} states · mutant {grh.get('mutant_violations_detected','-')}</span></div><div class="panel">Grover target hit rate<b>{gh.get('hit_rate','-')}</b><span>{gh.get('shots','-')} shots</span></div><div class="panel">동적 위험 Grover<b>{drg.get('hit_rate','-')}</b><span>mask {drg.get('target_mask','-')} · {drg.get('shots','-')} shots</span></div><div class="panel">Q# 인증 권고<b>{crh.get('required_auth_mode','-')}</b><span>Q# risk {crh.get('qsharp_risk_score','-')} · sensitive {crh.get('quantum_sensitive_features','-')}</span></div></section>
<h2>Q# 공격 회로 자원 추정</h2><div class="panel"><table><thead><tr><th>Register</th><th>Logical qubits</th><th>Logical depth</th><th>Physical qubits</th><th>Runtime/round</th></tr></thead><tbody>{estimates}</tbody></table><p class="muted">정책 공격 1라운드 기준이며 secp256k1 전체 Shor 공격 추정치는 아닙니다.</p></div>
<h2>취약점 및 검토 항목</h2><div class="toolbar"><input id="search" placeholder="규칙, 파일, 설명 검색" oninput="applyFilters()"><select id="severity" onchange="applyFilters()"><option value="all">모든 심각도</option>{''.join(f'<option value="{k}">{k.upper()}</option>' for k in summary)}</select><span id="visibleCount"></span></div><section id="findings">{findings}</section>
<h2>도구 실행 결과</h2>{tools}
<h2>무결성</h2><div class="panel"><code>{html.escape(report.manifest_hash)}</code><p class="muted">선택된 소스와 산출물의 SHA-256 manifest fingerprint</p></div>
</main><script>
function filterSeverity(value){{document.getElementById('severity').value=value;applyFilters()}}function applyFilters(){{const q=document.getElementById('search').value.toLowerCase();const s=document.getElementById('severity').value;let n=0;document.querySelectorAll('.finding').forEach(el=>{{const show=(s==='all'||el.dataset.severity===s)&&el.dataset.search.includes(q);el.style.display=show?'block':'none';if(show)n++}});document.getElementById('visibleCount').textContent=`${{n}}건 표시`}}applyFilters();
</script></body></html>"""
    output.write_text(document, encoding="utf-8")
