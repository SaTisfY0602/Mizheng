"""统一运行入口。

```text
.venv\\Scripts\\python.exe -m mvp_flow complete
.venv\\Scripts\\python.exe -m mvp_flow missing_binding
.venv\\Scripts\\python.exe -m mvp_flow --all
```

两组样例走同一条链路、同一个入口；每个阶段的实现性质（真实/替身）和成败都会打印
出来，同时落盘到 ``results/<样例名>/run-record.json``。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .pipeline import (
    CASE_DESCRIPTIONS,
    CASE_FILES,
    CONTRACT_CASES,
    FAILED,
    MODE_FIXTURE,
    MODE_REAL,
    REAL_CASES,
    SKIPPED,
    SUCCEEDED,
    RunRecord,
    run_all,
    run_case,
    utc_from_iso,
)

_STATUS_MARKS = {SUCCEEDED: "OK  ", FAILED: "FAIL", SKIPPED: "SKIP"}


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.all and args.case:
        parser.error("--all 与具体样例名不能同时使用")
    if not args.all and not args.case:
        parser.error("请指定样例名，或使用 --all")

    try:
        now = utc_from_iso(args.now) if args.now else None
    except ValueError as exc:
        parser.error(str(exc))

    output_root = Path(args.out).resolve() if args.out else None
    if args.all:
        records = run_all(output_root=output_root, now=now, mode=args.mode)
    else:
        records = [run_case(args.case, output_root=output_root, now=now, mode=args.mode)]

    for record in records:
        _print_record(record)

    return 0 if all(r.overall_status == SUCCEEDED for r in records) else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m mvp_flow",
        description="统一运行入口：按同一链路处理契约样例，输出报告、证据包和运行记录。",
    )
    parser.add_argument(
        "case",
        nargs="?",
        choices=sorted(set(CASE_FILES) | set(REAL_CASES)),
        help="样例名（fixture 模式仅支持 %s；real 模式支持 %s）"
        % (", ".join(CONTRACT_CASES), ", ".join(REAL_CASES)),
    )
    parser.add_argument("--all", action="store_true", help="按固定顺序跑完两组样例")
    parser.add_argument(
        "--mode",
        choices=[MODE_FIXTURE, MODE_REAL],
        default=MODE_FIXTURE,
        help="fixture=读契约样例快照（替身）；real=解析 examples/materials 下的真实材料",
    )
    parser.add_argument("--out", metavar="DIR", help="输出根目录（默认仓库下的 results/）")
    parser.add_argument(
        "--now",
        metavar="ISO8601",
        help="固定生成时刻，例如 2026-09-28T08:00:00Z；不传则用当前 UTC 时间",
    )
    return parser


def _print_record(record: RunRecord) -> None:
    print()
    print(f"=== {record.case_name} — {CASE_DESCRIPTIONS.get(record.case_name, '')} ===")
    print(f"  样例文件 : {record.sample_file}")
    print(f"  运行模式 : {record.mode}")
    print(f"  提交号   : {record.head_commit}")
    print(f"  接口版本 : {record.interface_version}")
    print(f"  规则版本 : {record.rule_version}")
    print(f"  核查时间 : {record.evaluation_time}")
    print(f"  流程状态 : {record.overall_status}")
    print(f"  结论状态 : {record.conclusion_state}")
    print("  阶段明细 :")
    for stage in record.stages:
        mark = _STATUS_MARKS.get(stage.status, stage.status)
        print(
            f"    [{mark}] {stage.implementation:<11} {stage.owner} "
            f"{stage.stage:<14} {stage.detail}"
        )
    if record.report_path:
        print(f"  报告     : {record.report_path}")
    if record.bundle_path:
        print(f"  证据包   : {record.bundle_path}")
    if record.verification:
        verification = record.verification
        print(
            f"  独立核验 : 完整性 {verification['integrity_status']}"
            f" / 重放 {verification['replay_status']}"
        )
        codes = [error["code"] for error in verification["errors"]]
        print(f"             错误码 {codes or '无'}")
        print(f"             说明：{verification['display_note']}")
    if record.failure_reason:
        print(f"  失败原因 : {record.failure_reason}")
    print(f"  运行记录 : {record.record_path}")


if __name__ == "__main__":
    sys.exit(main())
