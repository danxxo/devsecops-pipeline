#!/usr/bin/env python3
"""Централизованный DevSecOps quality-gate.

Блокирует только НОВЫЕ находки: сравнивает находки сканеров с baseline (снимком
известных находок master) и роняет сборку, если появилась новая находка с
severity >= порога из policy.yml. Вся логика «что роняет сборку» живёт здесь и в
policy.yml — в workflow нет ни --error, ни exit-code.

Две команды:
    python3 pipeline/gate.py                    # проверить (exit 1 при новых блокерах)
    python3 pipeline/gate.py --update-baseline  # пересохранить baseline (на push в master)
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path

# merge_reports лежит рядом — переиспользуем его парсеры и модель Finding.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from merge_reports import SEVERITY_ORDER, Finding, collect  # noqa: E402

try:
    import yaml
except ImportError:
    sys.exit("PyYAML не установлен. pip install pyyaml")


REPORTS_DIR = Path("pipeline/_reports")
POLICY = Path("pipeline/policy.yml")
BASELINE = Path("pipeline/_baseline/baseline.json")

_LINE = re.compile(r":\d+$")


def fingerprint(f: Finding) -> str:
    """Стабильный id находки: tool | rule_id | путь-без-номера-строки.
    Номер строки не включаем — он плывёт при правках выше по файлу."""
    loc = _LINE.sub("", f.location or "")
    if f.tool == "zap":
        loc = loc.split("?", 1)[0]  # query-string у URI шумит
    return hashlib.sha1(f"{f.tool}|{f.rule_id}|{loc}".encode()).hexdigest()[:16]


def threshold(policy: dict, tool: str) -> int | None:
    """Ранг severity, с которого находка инструмента блокирует. None = never."""
    tools = policy.get("tools", {})
    fo = tools.get(tool) or tools.get(tool.split()[0] if tool else tool, "never")
    fo = str(fo).lower()
    return None if fo == "never" else SEVERITY_ORDER.get(fo)


def load_baseline(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        return set(json.loads(path.read_text()).get("fingerprints", {}))
    except Exception:
        return set()


def save_baseline(path: Path, findings: list[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fps = {fingerprint(f): {"tool": f.tool, "severity": f.severity, "rule_id": f.rule_id,
                            "location": f.location} for f in findings}
    path.write_text(json.dumps({
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "commit": os.environ.get("GITHUB_SHA", "local"),
        "fingerprints": fps,
    }, indent=2, ensure_ascii=False))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--reports-dir", type=Path, default=REPORTS_DIR)
    p.add_argument("--policy", type=Path, default=POLICY)
    p.add_argument("--baseline", type=Path, default=BASELINE)
    p.add_argument("--update-baseline", action="store_true",
                   help="пересохранить baseline из текущих находок и выйти (на master)")
    args = p.parse_args(argv)

    policy = yaml.safe_load(args.policy.read_text()) or {}
    reports = collect(args.reports_dir)
    findings = [f for r in reports if r.status == "ok" for f in r.findings]

    # Режим master: просто фиксируем текущее состояние как новый baseline.
    if args.update_baseline:
        save_baseline(args.baseline, findings)
        print(f"baseline обновлён: {len(findings)} находок → {args.baseline}")
        return 0

    baseline = load_baseline(args.baseline)
    new_fps = {fingerprint(f) for f in findings} - baseline

    blockers: list[str] = []
    warns: list[str] = []

    # Сканер с порогом обязан был отработать — иначе гейт обходится поломкой сканера.
    for r in reports:
        if threshold(policy, r.name) is not None and r.status != "ok":
            blockers.append(f"[{r.name}] сканер не дал отчёт: {r.status} ({r.note})")

    for f in findings:
        fp = fingerprint(f)
        if fp not in new_fps:
            continue  # known — в baseline, гейт не трогает
        th = threshold(policy, f.tool)
        line = f"[{f.tool}] {f.severity} {f.rule_id} — {f.title} @ {f.location} (fp {fp})"
        if th is not None and SEVERITY_ORDER.get(f.severity, 99) <= th:
            blockers.append(line)
        else:
            warns.append(line)

    passed = not blockers
    fixed = len(baseline - {fingerprint(f) for f in findings})

    # --- вывод ---
    out = [
        f"Security Gate: {'PASS ✅' if passed else 'FAIL ❌'}",
        f"новых: {len(new_fps)} · блокеров: {len(blockers)} · warn: {len(warns)} · закрыто: {fixed}",
    ]
    if blockers:
        out += ["", "Блокирующие (новые находки выше порога):"] + [f"  ✗ {b}" for b in blockers]
    print("\n".join(out))

    # GitHub: аннотации на диффе + таблица в Summary прогона.
    for b in blockers:
        print(f"::error::{b}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        md = [f"## Security Gate: {'✅ PASS' if passed else '❌ FAIL'}",
              f"новых **{len(new_fps)}** · блокеров **{len(blockers)}** · warn {len(warns)} · закрыто {fixed}", ""]
        if blockers:
            md += ["| | Находка |", "|---|---|"] + [f"| ✗ | {b} |" for b in blockers]
        Path(summary).write_text("\n".join(md) + "\n")

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
