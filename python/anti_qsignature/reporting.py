from __future__ import annotations

import html
import json
from pathlib import Path

from .models import ScanReport


def write_json(report: ScanReport, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")


def write_html(report: ScanReport, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    summary = report.summary()
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(item.severity.upper())}</td>"
        f"<td>{html.escape(item.rule_id)}</td>"
        f"<td>{html.escape(item.title)}</td>"
        f"<td>{html.escape(item.path)}:{item.line}</td>"
        f"<td><code>{html.escape(item.evidence)}</code><br>{html.escape(item.remediation)}</td>"
        "</tr>"
        for item in report.findings
    )
    document = f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><title>Anti-QSignature Report</title>
<style>
body{{font:15px system-ui;max-width:1200px;margin:40px auto;padding:0 20px;color:#172033}}
h1{{margin-bottom:4px}} .cards{{display:flex;gap:12px;flex-wrap:wrap}}
.card{{padding:12px 18px;border:1px solid #d9deea;border-radius:10px;background:#f8faff}}
table{{border-collapse:collapse;width:100%;margin-top:20px}}th,td{{border:1px solid #d9deea;padding:9px;vertical-align:top;text-align:left}}
code{{word-break:break-all}} pre{{background:#101827;color:#dce7ff;padding:16px;overflow:auto;border-radius:10px}}
</style></head><body>
<h1>Anti-QSignature 보안 보고서</h1>
<p>대상: <code>{html.escape(report.target)}</code><br>Manifest SHA-256: <code>{report.manifest_hash}</code></p>
<div class="cards">{''.join(f'<div class="card"><b>{k.upper()}</b><br>{v}</div>' for k,v in summary.items())}</div>
<h2>취약점 후보</h2><table><thead><tr><th>심각도</th><th>규칙</th><th>제목</th><th>위치</th><th>근거 및 조치</th></tr></thead><tbody>{rows}</tbody></table>
<h2>정책 퍼징</h2><pre>{html.escape(json.dumps(report.policy_fuzz, indent=2, ensure_ascii=False))}</pre>
<h2>Q# 양자 분석</h2><pre>{html.escape(json.dumps(report.quantum, indent=2, ensure_ascii=False))}</pre>
<h2>외부 도구</h2><pre>{html.escape(json.dumps([tool.to_dict() for tool in report.tools], indent=2, ensure_ascii=False))}</pre>
</body></html>"""
    output.write_text(document, encoding="utf-8")

