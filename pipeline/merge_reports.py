#!/usr/bin/env python3
"""Агрегация JSON-отчётов всех DevSecOps-сканеров в единый HTML.

Использование:
    python3 pipeline/merge_reports.py [--reports-dir DIR] [--output FILE]

По умолчанию читает из pipeline/_reports/, пишет в pipeline/_reports/report.html.
Отсутствие конкретного JSON не ошибка — секция помечается как "не запускалось".

Поддерживаемые форматы (на 2026-05):
  semgrep.json        — Semgrep CLI 1.x, --json
  gosec.json          — gosec 2.x, -fmt=json
  checkov.json        — Checkov, -o json (массив фреймворков)
  govulncheck.json    — govulncheck 1.x, NDJSON
  trivy.json          — Trivy 0.x, --format json
  zap.json            — ZAP baseline, -J <name>
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# --- модель -----------------------------------------------------------------


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


@dataclass
class Finding:
    tool: str
    severity: str  # critical|high|medium|low|info|unknown
    rule_id: str
    title: str
    location: str = ""
    description: str = ""

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class ToolReport:
    name: str
    status: str  # ok | missing | parse_error
    findings: list[Finding] = field(default_factory=list)
    note: str = ""

    @property
    def severity_counts(self) -> dict[str, int]:
        out = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


# --- парсеры ----------------------------------------------------------------


def _norm_sev(raw: str) -> str:
    s = (raw or "").lower()
    if s in {"critical", "crit"}:
        return "critical"
    if s in {"high", "error"}:
        return "high"
    if s in {"medium", "warning", "warn"}:
        return "medium"
    if s in {"low", "info"}:
        return "low"
    if s in {"informational", "note"}:
        return "info"
    return "unknown"


def parse_semgrep(path: Path) -> list[Finding]:
    data = json.loads(path.read_text())
    out: list[Finding] = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        loc = f"{r.get('path','')}:{(r.get('start') or {}).get('line','?')}"
        out.append(
            Finding(
                tool="semgrep",
                severity=_norm_sev(extra.get("severity", "")),
                rule_id=r.get("check_id", ""),
                title=(extra.get("message", "") or "").strip().split("\n", 1)[0][:200],
                location=loc,
                description=(extra.get("message", "") or "").strip(),
            )
        )
    return out


def parse_gosec(path: Path) -> list[Finding]:
    data = json.loads(path.read_text())
    out: list[Finding] = []
    for i in data.get("Issues", []):
        # Путь в gosec абсолютный — режем до repo-relative.
        f = i.get("file", "")
        if "/devsecops/" in f:
            f = f.split("/devsecops/", 1)[1]
        loc = f"{f}:{i.get('line','?')}"
        out.append(
            Finding(
                tool="gosec",
                severity=_norm_sev(i.get("severity", "")),
                rule_id=i.get("rule_id", ""),
                title=i.get("details", "")[:200],
                location=loc,
                description=f"{i.get('details','')}\n\nCode:\n{i.get('code','')}",
            )
        )
    return out


def parse_checkov(path: Path) -> list[Finding]:
    raw = json.loads(path.read_text())
    # Checkov с -d возвращает либо dict (один фреймворк), либо list (несколько).
    frameworks = raw if isinstance(raw, list) else [raw]
    out: list[Finding] = []
    for fw in frameworks:
        check_type = fw.get("check_type", "")
        for c in (fw.get("results") or {}).get("failed_checks", []):
            file_path = c.get("file_path", "")
            line = (c.get("file_line_range") or [None, None])[0]
            loc = f"{file_path}:{line}" if line else file_path
            out.append(
                Finding(
                    tool=f"checkov ({check_type})" if check_type else "checkov",
                    # Checkov severity не выдаёт стабильно — для unified ставим medium.
                    severity="medium",
                    rule_id=c.get("check_id", ""),
                    title=c.get("check_name", "")[:200],
                    location=loc,
                    description=c.get("guideline", "") or c.get("check_name", ""),
                )
            )
    return out


def parse_govulncheck(path: Path) -> list[Finding]:
    """govulncheck выдаёт NDJSON: цепочка объектов одного из типов:
    - osv: запись об уязвимости (метаданные CVE)
    - finding: вызов из кода в уязвимый символ (call trace)
    Берём только finding-и c trace=on (где есть реальный путь),
    обогащаем заголовком из osv-словаря.
    """
    osvs: dict[str, dict] = {}
    findings_raw: list[dict] = []
    decoder = json.JSONDecoder()
    text = path.read_text()
    pos = 0
    while pos < len(text):
        while pos < len(text) and text[pos] in " \n\r\t":
            pos += 1
        if pos >= len(text):
            break
        obj, end = decoder.raw_decode(text, pos)
        pos = end
        if "osv" in obj:
            osv = obj["osv"]
            osvs[osv["id"]] = osv
        elif "finding" in obj:
            findings_raw.append(obj["finding"])

    out: list[Finding] = []
    seen: set[str] = set()
    for fr in findings_raw:
        osv_id = fr.get("osv", "")
        # Только finding-и с trace (call-graph reachable) и непустым trace[0].position
        traces = fr.get("trace") or []
        if not traces or not traces[0].get("position"):
            continue
        first = traces[0]
        pos_obj = first.get("position", {})
        loc = f"{pos_obj.get('filename','')}:{pos_obj.get('line','?')}"
        key = f"{osv_id}@{loc}"
        if key in seen:
            continue
        seen.add(key)
        osv = osvs.get(osv_id, {})
        title = osv.get("summary", "") or osv_id
        # govulncheck severity не выдаёт; берём по CVSS если есть, иначе high
        # (раз код реально достижим — по умолчанию high).
        sev = "high"
        out.append(
            Finding(
                tool="govulncheck",
                severity=sev,
                rule_id=osv_id,
                title=f"{osv_id}: {title}"[:200],
                location=loc,
                description=osv.get("details", "") or title,
            )
        )
    return out


def parse_trivy(path: Path) -> list[Finding]:
    data = json.loads(path.read_text())
    out: list[Finding] = []
    for res in data.get("Results", []):
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            out.append(
                Finding(
                    tool="trivy",
                    severity=_norm_sev(v.get("Severity", "")),
                    rule_id=v.get("VulnerabilityID", ""),
                    title=f"{v.get('PkgName','')} {v.get('InstalledVersion','')}: {v.get('Title','')}"[:200],
                    location=target,
                    description=v.get("Description", "") or v.get("Title", ""),
                )
            )
        for s in res.get("Secrets") or []:
            out.append(
                Finding(
                    tool="trivy",
                    severity=_norm_sev(s.get("Severity", "")),
                    rule_id=s.get("RuleID", ""),
                    title=f"Secret: {s.get('Title','')}"[:200],
                    location=f"{target}:{s.get('StartLine','?')}",
                    description=s.get("Match", ""),
                )
            )
        for m in res.get("Misconfigurations") or []:
            out.append(
                Finding(
                    tool="trivy",
                    severity=_norm_sev(m.get("Severity", "")),
                    rule_id=m.get("ID", ""),
                    title=f"Misconfig: {m.get('Title','')}"[:200],
                    location=target,
                    description=m.get("Description", "") or m.get("Title", ""),
                )
            )
    return out


def parse_zap(path: Path) -> list[Finding]:
    data = json.loads(path.read_text())
    out: list[Finding] = []
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            risk_map = {"3": "high", "2": "medium", "1": "low", "0": "info"}
            sev = risk_map.get(str(a.get("riskcode", "")), _norm_sev(a.get("riskdesc", "")))
            instances = a.get("instances", []) or []
            loc = instances[0].get("uri", "") if instances else site.get("@name", "")
            out.append(
                Finding(
                    tool="zap",
                    severity=sev,
                    rule_id=a.get("pluginid", ""),
                    title=a.get("name", "")[:200],
                    location=loc,
                    description=a.get("desc", "") or a.get("solution", ""),
                )
            )
    return out


# --- сборка отчётов ---------------------------------------------------------


PARSERS = {
    "semgrep": ("semgrep.json", parse_semgrep),
    "gosec": ("gosec.json", parse_gosec),
    "checkov": ("checkov.json", parse_checkov),
    "govulncheck": ("govulncheck.json", parse_govulncheck),
    "trivy": ("trivy.json", parse_trivy),
    "zap": ("zap.json", parse_zap),
}


def collect(reports_dir: Path) -> list[ToolReport]:
    out: list[ToolReport] = []
    for name, (filename, fn) in PARSERS.items():
        p = reports_dir / filename
        if not p.exists() or p.stat().st_size == 0:
            out.append(ToolReport(name=name, status="missing", note="JSON не найден"))
            continue
        try:
            findings = fn(p)
            out.append(ToolReport(name=name, status="ok", findings=findings))
        except Exception as e:  # noqa: BLE001
            out.append(ToolReport(name=name, status="parse_error", note=f"{type(e).__name__}: {e}"))
    return out


# --- HTML рендер ------------------------------------------------------------


SEVERITY_COLORS = {
    "critical": "#7d0000",
    "high": "#c0392b",
    "medium": "#d68910",
    "low": "#2980b9",
    "info": "#7f8c8d",
    "unknown": "#95a5a6",
}


def render_html(reports: list[ToolReport]) -> str:
    total_findings = sum(len(r.findings) for r in reports)
    overall_counts: dict[str, int] = {k: 0 for k in SEVERITY_ORDER}
    for r in reports:
        for sev, n in r.severity_counts.items():
            overall_counts[sev] += n

    def severity_chip(sev: str, count: int) -> str:
        color = SEVERITY_COLORS.get(sev, "#666")
        return (
            f'<span class="chip" style="background:{color}">'
            f"{html.escape(sev)}: {count}"
            f"</span>"
        )

    summary_chips = " ".join(severity_chip(s, n) for s, n in overall_counts.items() if n)

    sections: list[str] = []
    for r in reports:
        sections.append(_render_tool_section(r))

    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>DevSecOps Unified Report — log-api</title>
  <style>
    body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 1100px; margin: 2em auto; padding: 0 1em; color: #2c3e50; }}
    h1 {{ margin-bottom: 0.2em; }}
    .summary {{ background: #ecf0f1; padding: 1em 1.4em; border-radius: 6px; margin: 1em 0 2em; }}
    .summary .total {{ font-size: 1.6em; font-weight: 600; }}
    .chip {{ display: inline-block; color: white; padding: 2px 10px; border-radius: 12px; font-size: 0.85em; margin-right: 6px; }}
    details {{ margin: 1em 0; border: 1px solid #ddd; border-radius: 6px; }}
    summary {{ padding: 0.8em 1em; cursor: pointer; background: #f7f9fa; font-weight: 600; }}
    summary:hover {{ background: #eef2f4; }}
    .tool-status {{ font-weight: 400; color: #7f8c8d; margin-left: 0.5em; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 0.5em 0.8em; border-bottom: 1px solid #eee; text-align: left; vertical-align: top; }}
    th {{ background: #fafafa; font-size: 0.9em; }}
    code {{ background: #f4f6f7; padding: 1px 5px; border-radius: 3px; font-size: 0.9em; }}
    .empty {{ padding: 1em; color: #7f8c8d; font-style: italic; }}
    .desc {{ font-size: 0.85em; color: #555; max-width: 480px; }}
  </style>
</head>
<body>
  <h1>DevSecOps Unified Report</h1>
  <p style="color:#7f8c8d">log-api</p>

  <div class="summary">
    <div class="total">{total_findings} finding-ов суммарно</div>
    <div style="margin-top: 0.6em">{summary_chips or '<span style="color:#27ae60">все сканеры чисты</span>'}</div>
  </div>

  {''.join(sections)}
</body>
</html>
"""


def _render_tool_section(r: ToolReport) -> str:
    if r.status == "missing":
        return (
            f'<details><summary>{html.escape(r.name)}'
            f'<span class="tool-status">не запускалось</span></summary>'
            f'<div class="empty">{html.escape(r.note)}</div></details>'
        )
    if r.status == "parse_error":
        return (
            f'<details open><summary>{html.escape(r.name)}'
            f'<span class="tool-status">ошибка парсинга</span></summary>'
            f'<div class="empty">{html.escape(r.note)}</div></details>'
        )
    counts = r.severity_counts
    chips = " ".join(
        f'<span class="chip" style="background:{SEVERITY_COLORS.get(s, "#666")}">'
        f"{html.escape(s)}: {n}</span>"
        for s, n in counts.items()
        if n
    )
    if not r.findings:
        body = '<div class="empty">finding-ов нет — все проверки пройдены.</div>'
    else:
        rows: list[str] = []
        sorted_findings = sorted(r.findings, key=lambda f: (f.severity_rank, f.rule_id))
        for f in sorted_findings:
            rows.append(
                "<tr>"
                f'<td><span class="chip" style="background:{SEVERITY_COLORS.get(f.severity, "#666")}">'
                f"{html.escape(f.severity)}</span></td>"
                f"<td><code>{html.escape(f.rule_id)}</code></td>"
                f'<td>{html.escape(f.title)}<div class="desc">{html.escape(f.description[:300])}</div></td>'
                f"<td><code>{html.escape(f.location)}</code></td>"
                "</tr>"
            )
        body = (
            "<table>"
            "<thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Location</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody>"
            "</table>"
        )
    return (
        f'<details><summary>{html.escape(r.name)} ({len(r.findings)}) {chips}</summary>'
        f"{body}</details>"
    )


# --- main -------------------------------------------------------------------


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--reports-dir", type=Path, default=Path("pipeline/_reports"))
    p.add_argument("--output", type=Path, default=None)
    args = p.parse_args(argv)

    reports_dir: Path = args.reports_dir
    if not reports_dir.is_dir():
        print(f"reports-dir не существует: {reports_dir}", file=sys.stderr)
        return 1

    output: Path = args.output or (reports_dir / "report.html")
    reports = collect(reports_dir)
    output.write_text(render_html(reports))

    total = sum(len(r.findings) for r in reports)
    ok = sum(1 for r in reports if r.status == "ok")
    print(f"Tools: {ok}/{len(reports)} parsed, total findings: {total}")
    print(f"Report → {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
