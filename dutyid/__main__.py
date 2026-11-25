"""命令行入口：运行全部离线复查并输出结构化报告。

用法（原生 Windows，Python 3.12，标准库）：

    python -m dutyid              # 跑全部，打印摘要 + 写 report.json
    python -m dutyid --json       # 只打印 JSON 报告到 stdout
    python -m dutyid --workdir X  # 指定工作目录（默认临时目录）

退出码：全部通过 0；有失败 1。
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from . import modelcheck, scale, scenarios


def build_report(workdir: Path) -> dict:
    report: dict = {"tool": "dutyid", "version": "1.0.0", "sections": {}}

    # 场景 A
    wa = workdir / "scenario-A"
    ra = scenarios.scenario_revoke_first(str(wa))
    report["sections"]["scenario_A_revoke_first"] = {
        "name": ra.name,
        "description": ra.description,
        "threads": ra.threads_used,
        "barriers": ra.barriers_used,
        "trace": ra.trace,
        "verify": ra.verify.to_dict(),
        "evidence": {
            k: v.to_dict() for k, v in ra.evidence_verify.items()
        },
        "expectations": [{"name": n, "passed": p} for n, p in ra.expectations],
        "valid_set": sorted(ra.recovered.valid),
        "notes": ra.recovered.notes,
        "ok": ra.ok,
    }

    # 场景 B
    wb = workdir / "scenario-B"
    rb = scenarios.scenario_lost_ack_replay(str(wb))
    report["sections"]["scenario_B_lost_ack_replay"] = {
        "name": rb.name,
        "description": rb.description,
        "threads": rb.threads_used,
        "barriers": rb.barriers_used,
        "trace": rb.trace,
        "verify": rb.verify.to_dict(),
        "evidence": {
            k: v.to_dict() for k, v in rb.evidence_verify.items()
        },
        "expectations": [{"name": n, "passed": p} for n, p in rb.expectations],
        "valid_set": sorted(rb.recovered.valid),
        "notes": rb.recovered.notes,
        "ok": rb.ok,
    }

    # 穷举（深度 6 足以覆盖“换根致同源 / 旧代重投”等 6 步短交错）
    mc = modelcheck.explore(max_depth=6)
    report["sections"]["exhaustive_interleavings"] = {
        "max_depth": mc.max_depth,
        "states": mc.states,
        "transitions": mc.transitions,
        "violations": [
            {"invariant": v.invariant, "path": v.path, "detail": v.detail}
            for v in mc.violations
        ],
        "named_scenarios": mc.named,
        "ok": mc.ok,
    }

    # 规模
    sc = scale.run()
    report["sections"]["scale_60k_org_isolation"] = sc.to_dict()

    report["ok"] = all(
        sec.get("ok", False) for sec in report["sections"].values()
    )
    return report


def _summary(report: dict) -> str:
    lines: list[str] = []
    ok_all = report["ok"]
    lines.append("=" * 72)
    lines.append("离线值班身份签发 · 安全复核报告")
    lines.append("=" * 72)
    for key, sec in report["sections"].items():
        status = "通过" if sec.get("ok") else "失败"
        lines.append(f"\n[{status}] {key}")
        if key.startswith("scenario"):
            for e in sec["expectations"]:
                lines.append(f"    - {'✓' if e['passed'] else '✗'} {e['name']}")
            if sec["verify"].get("findings"):
                for f in sec["verify"]["findings"]:
                    lines.append(f"    · 检出分歧: {f}")
            for k, ev in sec["evidence"].items():
                lines.append(
                    f"    · 证据({k}): {ev['evidence_results'].get('conflict_kind')} "
                    f"最小={ev['evidence_results'].get('minimal')} "
                    f"digest={ev['evidence_results'].get('digest','')[:16]}"
                )
        elif key == "exhaustive_interleavings":
            lines.append(
                f"    状态={sec['states']} 迁移={sec['transitions']} "
                f"反例={len(sec['violations'])}"
            )
            for v in sec["violations"][:5]:
                lines.append(f"    ✗ {v['invariant']}: {v['detail']} 路径={v['path']}")
        elif key == "scale_60k_org_isolation":
            c = sec["counts"]
            lines.append(
                f"    记录={sec['total_records']} 目标={sec['target']}"
            )
            lines.append(
                f"    实际范围={c['actual_scope']} 全量={c['full_result']} "
                f"越界={c['overreach']}"
            )
            for chk in sec["checks"]:
                lines.append(f"    - {'✓' if chk['passed'] else '✗'} {chk['name']}")
            for n in sec["notes"]:
                lines.append(f"    · {n}")
    lines.append("\n" + "=" * 72)
    lines.append("总体：" + ("全部通过" if ok_all else "存在失败"))
    lines.append("=" * 72)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m dutyid", description=__doc__)
    ap.add_argument("--json", action="store_true", help="只输出 JSON")
    ap.add_argument("--workdir", type=str, default=None, help="工作目录")
    ap.add_argument("--report", type=str, default=None, help="报告输出路径")
    args = ap.parse_args(argv)

    # Windows 控制台默认可能是 GBK/cp936，直接打印中文摘要会 UnicodeEncodeError。
    # 尽量把标准输出切到 UTF-8；不支持则降到可安全替换的错误处理器。
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError, OSError):
        pass

    if args.workdir:
        workdir = Path(args.workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        report = build_report(workdir)
    else:
        with tempfile.TemporaryDirectory(prefix="dutyid-") as td:
            report = build_report(Path(td))

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(_summary(report))

    out = Path(args.report) if args.report else Path("report.json")
    try:
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), "utf-8")
        if not args.json:
            print(f"\n报告已写入: {out.resolve()}")
    except OSError as exc:
        print(f"警告：报告写入失败: {exc}", file=sys.stderr)

    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
