"""统一运行入口。

```text
# 仓库预置样例
.venv\\Scripts\\python.exe -m mvp_flow complete --mode real
.venv\\Scripts\\python.exe -m mvp_flow --all --mode real

# 外部案例目录（非预置输入）
.venv\\Scripts\\python.exe -m mvp_flow my-case --mode real --case-dir D:\\cases\\my-case
```

每次运行落在 ``<输出根>/<案例名>/runs/<run_id>/``，带自己的
``run-record.json``；不同运行不互相覆盖。默认输出根是仓库下的 ``results/``，
验收时建议用 ``--out`` 指到一个新的空目录。
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
    if args.all and args.case_dir:
        parser.error("--all 只跑仓库预置样例，不能与 --case-dir 同时使用")
    if not args.all and not args.case:
        parser.error("请指定样例名，或使用 --all")
    if args.case_dir:
        if args.mode != MODE_REAL:
            parser.error("--case-dir 只在 --mode real 下支持")
    elif args.case and args.case not in (set(CASE_FILES) | set(REAL_CASES)):
        allowed = sorted(set(CASE_FILES) | set(REAL_CASES))
        parser.error(
            f"未知样例 {args.case!r}；仓库预置样例为 {allowed}，外部案例请配合 --case-dir 使用"
        )

    try:
        now = utc_from_iso(args.now) if args.now else None
    except ValueError as exc:
        parser.error(str(exc))

    output_root = Path(args.out).resolve() if args.out else None
    case_source = Path(args.case_dir).resolve() if args.case_dir else None
    try:
        if args.all:
            records = run_all(
                output_root=output_root,
                now=now,
                mode=args.mode,
                run_id=args.run_id,
            )
        else:
            records = [
                run_case(
                    args.case,
                    output_root=output_root,
                    case_source_dir=case_source,
                    run_id=args.run_id,
                    now=now,
                    mode=args.mode,
                )
            ]
    except ValueError as exc:
        parser.error(str(exc))

    for record in records:
        _print_record(record)

    return 0 if all(r.overall_status == SUCCEEDED for r in records) else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m mvp_flow",
        description="统一运行入口：按同一链路处理案例，输出报告、证据包和运行记录。",
    )
    parser.add_argument(
        "case",
        nargs="?",
        help="案例名。用仓库预置样例时取 %s（real）或 %s（fixture）；"
        "配合 --case-dir 时可自取一个名字。"
        % (", ".join(REAL_CASES), ", ".join(CONTRACT_CASES)),
    )
    parser.add_argument("--all", action="store_true", help="按固定顺序跑完仓库预置样例")
    parser.add_argument(
        "--mode",
        choices=[MODE_FIXTURE, MODE_REAL],
        default=MODE_FIXTURE,
        help="fixture=读契约样例快照（替身）；real=解析真实材料（预置目录或 --case-dir）",
    )
    parser.add_argument(
        "--case-dir",
        metavar="DIR",
        help="外部案例目录（只读）：目录内放 case.json、可选 review_events.json 与材料文件，"
        "需配合 --mode real。案例名由位置参数给出。",
    )
    parser.add_argument(
        "--out",
        metavar="DIR",
        help="输出根目录（默认仓库下的 results/）。产物落在 <DIR>/<案例名>/runs/<run_id>/",
    )
    parser.add_argument(
        "--run-id",
        metavar="NAME",
        help="运行标识（默认取本次执行时钟）。同一标识重复运行是幂等复现；"
        "不同标识落在不同目录，互不覆盖。",
    )
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
