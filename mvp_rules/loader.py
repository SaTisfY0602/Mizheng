"""规则包加载与静态校验。

规则包放在 ``mvp_rules/data/`` 下，按「包」组织成 JSON：

* ``meta``——包的标识与版本；``version`` 必须与快照 ``rule_version`` 一致。
* ``indicators``——标准指标目录（实现方案 §7.4.1 第一层内容库）。
* ``rules``——已实现的规则清单（第二层内容库），每条规则关联指标项与辅助核查单元。

加载时刻意做**严格静态校验**，宁可在启动时失败，也不要让一条写错 ``indicator_id``
或 ``tool_unit`` 的规则悄悄进到报告里：

* ``meta.id`` / ``rule_id`` / ``indicator_id`` 都不能重复；
* 规则引用的 ``indicator_id`` 必须真实存在于目录中；
* ``layer`` 必须属于 ``RISK`` / ``DECISION`` / ``OPS``；
* ``tool_unit`` 必须是 ``U01``—``U16``（**内部单元编号，不是国标条款编号**）;
* 同一 ``rule_id`` 不能同时声明不同等级。
"""

from __future__ import annotations

import json
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from .model import Indicator, PackMeta, RuleSet, RuleSpec

DATA_DIR = Path(__file__).resolve().parent / "data"

# 实现方案 §7.4.2 的 16 类辅助核查单元（工具内部编号，不是国家标准条款编号）
TOOL_UNITS = tuple(f"U{index:02d}" for index in range(1, 17))

# 规则分层：风险识别 / 符合性判定 / 运行保障
LAYERS = ("RISK", "DECISION", "OPS")

_RESERVED_INDICATOR_FIELDS = {
    "indicator_id",
    "standard",
    "clause",
    "title",
    "domain",
    "levels",
    "level_clauses",
    "assessment_object",
    "required_materials",
    "check_method",
    "automated_rule_ids",
    "note",
}


class RulePackError(Exception):
    """规则包缺失、格式不合法或内部引用不一致。"""


def load_rule_set(data_dir: Path | None = None) -> RuleSet:
    """读取 ``data_dir`` 下全部 ``*.json``，合并成一个 :class:`RuleSet`。"""
    directory = Path(data_dir) if data_dir is not None else DATA_DIR
    if not directory.is_dir():
        raise RulePackError(f"规则包目录不存在：{directory}")

    paths = sorted(directory.glob("*.json"))
    if not paths:
        raise RulePackError(f"规则包目录为空：{directory}")

    indicators: list[Indicator] = []
    rules: list[RuleSpec] = []
    metas: list[PackMeta] = []
    payloads: list[dict] = []

    for path in paths:
        payload = _read_json(path)
        meta = _parse_meta(payload, path)
        metas.append(meta)
        payloads.append(payload)
        indicators.extend(_parse_indicators(payload, path))
        rules.extend(_parse_rules(payload, path, pack_id=meta.id))

    _check_versions(metas, paths)
    _check_unique(indicators, ("indicator_id",), "指标项")
    _check_unique(rules, ("rule_id",), "规则")
    indicator_ids = {item.indicator_id for item in indicators}
    _check_rule_references(rules, indicator_ids)
    _check_severity_conflicts(rules)
    rule_versions = _collect_rule_versions(payloads, rules)

    return RuleSet(
        meta=metas[0],
        indicators=tuple(indicators),
        rules=tuple(rules),
        rule_versions=rule_versions,
        source_dir=directory,
    )


def _collect_rule_versions(
    payloads: list[dict], rules: list[RuleSpec]
) -> Mapping[str, tuple[str, ...]]:
    """合并各文件的 ``meta.rule_versions``，并校验其中的规则 ID 都真实存在。"""
    declared: dict[str, list[str]] = {}
    for payload in payloads:
        meta = payload.get("meta") or {}
        table = meta.get("rule_versions", {})
        if not isinstance(table, dict):
            raise RulePackError("meta.rule_versions 必须是对象")
        for version, ids in table.items():
            if not isinstance(version, str) or not version:
                raise RulePackError(f"meta.rule_versions 的版本号必须是非空字符串：{version!r}")
            if not isinstance(ids, list) or not all(isinstance(v, str) for v in ids):
                raise RulePackError(f"meta.rule_versions[{version!r}] 必须是字符串数组")
            bucket = declared.setdefault(version, [])
            for rule_id in ids:
                if rule_id not in bucket:
                    bucket.append(rule_id)

    known = {spec.rule_id for spec in rules}
    for version, ids in declared.items():
        unknown = [rule_id for rule_id in ids if rule_id not in known]
        if unknown:
            raise RulePackError(
                f"meta.rule_versions[{version!r}] 引用了规则清单里不存在的规则：{unknown}"
            )
    return MappingProxyType({version: tuple(ids) for version, ids in declared.items()})


def _read_json(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - 只在文件系统异常时触发
        raise RulePackError(f"无法读取规则包 {path.name}：{exc}") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RulePackError(f"规则包 {path.name} 不是合法 JSON：{exc}") from exc
    if not isinstance(payload, dict):
        raise RulePackError(f"规则包 {path.name} 顶层必须是对象")
    return payload


def _parse_meta(payload: dict, path: Path) -> PackMeta:
    raw = payload.get("meta")
    if not isinstance(raw, dict):
        raise RulePackError(f"规则包 {path.name} 缺少 meta 对象")
    required = ("id", "version", "schema", "description", "created_at")
    missing = [key for key in required if not isinstance(raw.get(key), str) or not raw[key]]
    if missing:
        raise RulePackError(f"规则包 {path.name} 的 meta 缺少字段：{missing}")
    supersedes = raw.get("supersedes", [])
    if not isinstance(supersedes, list) or not all(isinstance(v, str) for v in supersedes):
        raise RulePackError(f"规则包 {path.name} 的 meta.supersedes 必须是字符串数组")
    return PackMeta(
        id=raw["id"],
        version=raw["version"],
        schema=raw["schema"],
        description=raw["description"],
        created_at=raw["created_at"],
        supersedes=tuple(supersedes),
    )


def _check_versions(metas: list[PackMeta], paths: list[Path]) -> None:
    versions = {meta.version for meta in metas}
    if len(versions) != 1:
        detail = "，".join(f"{meta.id}={meta.version}" for meta in metas)
        raise RulePackError(
            f"同一个规则包的各个文件版本必须一致，实际为 {detail}；"
            "版本不一致会让快照的 rule_version 无法回溯到确定的规则内容"
        )
    schemas = {meta.schema for meta in metas}
    if len(schemas) != 1:
        raise RulePackError(f"同一规则包的 schema 必须一致：{sorted(schemas)}")


def _parse_indicators(payload: dict, path: Path) -> list[Indicator]:
    raw = payload.get("indicators", [])
    if not isinstance(raw, list):
        raise RulePackError(f"规则包 {path.name} 的 indicators 必须是数组")
    result: list[Indicator] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise RulePackError(f"规则包 {path.name} 的 indicators[{index}] 必须是对象")
        unknown = set(item) - _RESERVED_INDICATOR_FIELDS
        if unknown:
            raise RulePackError(
                f"规则包 {path.name} 的 indicators[{index}] 含未知字段：{sorted(unknown)}"
            )
        for key in ("indicator_id", "standard", "clause", "title", "domain"):
            if not isinstance(item.get(key), str) or not item[key]:
                raise RulePackError(
                    f"规则包 {path.name} 的 indicators[{index}] 缺少必填字段 {key!r}"
                )
        levels = item.get("levels", [])
        if not isinstance(levels, list) or not all(
            isinstance(level, int) and not isinstance(level, bool) and 1 <= level <= 5
            for level in levels
        ):
            raise RulePackError(
                f"指标 {item['indicator_id']} 的 levels 必须是 1—5 的整数数组"
            )
        level_clauses = item.get("level_clauses", {})
        if not isinstance(level_clauses, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in level_clauses.items()
        ):
            raise RulePackError(
                f"指标 {item['indicator_id']} 的 level_clauses 必须是「等级→条款」的字符串映射"
            )
        # ``levels`` 与 ``level_clauses`` 是同一件事的两种写法，只保留一个真相：
        # 以 level_clauses 的键为准派生 levels；JSON 里若同时写了 levels，必须与之一致。
        declared_levels = set(levels)
        clause_levels = {int(level) for level in level_clauses}
        if declared_levels and declared_levels != clause_levels:
            raise RulePackError(
                f"指标 {item['indicator_id']} 的 levels {sorted(declared_levels)} "
                f"与 level_clauses 的等级 {sorted(clause_levels)} 不一致"
            )
        for key in ("required_materials", "automated_rule_ids"):
            value = item.get(key, [])
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise RulePackError(f"指标 {item['indicator_id']} 的 {key} 必须是字符串数组")
        if not isinstance(item.get("assessment_object", ""), str):
            raise RulePackError(f"指标 {item['indicator_id']} 的 assessment_object 必须是字符串")
        if not isinstance(item.get("check_method", ""), str):
            raise RulePackError(f"指标 {item['indicator_id']} 的 check_method 必须是字符串")
        level_clauses = item.get("level_clauses", {})
        if not isinstance(level_clauses, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in level_clauses.items()
        ):
            raise RulePackError(
                f"指标 {item['indicator_id']} 的 level_clauses 必须是「等级→条款」的字符串映射"
            )
        result.append(
            Indicator(
                indicator_id=item["indicator_id"],
                standard=item["standard"],
                clause=item["clause"],
                title=item["title"],
                domain=item["domain"],
                levels=tuple(sorted(clause_levels)),
                assessment_object=item.get("assessment_object", ""),
                required_materials=tuple(item.get("required_materials", [])),
                check_method=item.get("check_method", ""),
                automated_rule_ids=tuple(item.get("automated_rule_ids", [])),
                level_clauses=MappingProxyType(dict(level_clauses)),
                note=item.get("note", ""),
            )
        )
    return result


def _parse_rules(payload: dict, path: Path, *, pack_id: str) -> list[RuleSpec]:
    raw = payload.get("rules", [])
    if not isinstance(raw, list):
        raise RulePackError(f"规则包 {path.name} 的 rules 必须是数组")
    result: list[RuleSpec] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise RulePackError(f"规则包 {path.name} 的 rules[{index}] 必须是对象")
        rule_id = item.get("rule_id")
        if not isinstance(rule_id, str) or not rule_id:
            raise RulePackError(f"规则包 {path.name} 的 rules[{index}] 缺少 rule_id")
        for key in ("title", "layer", "indicator_id", "tool_unit", "evaluation"):
            if not isinstance(item.get(key), str) or not item[key]:
                raise RulePackError(f"规则 {rule_id} 缺少必填字段 {key!r}")
        layer = item["layer"]
        if layer not in LAYERS:
            raise RulePackError(f"规则 {rule_id} 的 layer 必须是 {LAYERS} 之一，实际为 {layer!r}")
        tool_unit = item["tool_unit"]
        if tool_unit not in TOOL_UNITS:
            raise RulePackError(
                f"规则 {rule_id} 的 tool_unit 必须是 U01—U16（工具内部单元编号），"
                f"实际为 {tool_unit!r}"
            )
        for key in ("standard_refs", "tested_by"):
            value = item.get(key, [])
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise RulePackError(f"规则 {rule_id} 的 {key} 必须是字符串数组")
        parameters = item.get("parameters", {})
        if not isinstance(parameters, dict):
            raise RulePackError(f"规则 {rule_id} 的 parameters 必须是对象")
        result.append(
            RuleSpec(
                rule_id=rule_id,
                pack=pack_id,
                title=item["title"],
                layer=layer,
                indicator_id=item["indicator_id"],
                tool_unit=tool_unit,
                evaluation=item["evaluation"],
                engine_entry=item.get("engine_entry", ""),
                condition=item.get("condition", ""),
                parameters=parameters,
                standard_refs=tuple(item.get("standard_refs", [])),
                tested_by=tuple(item.get("tested_by", [])),
            )
        )
    return result


def _check_unique(items, keys: tuple[str, ...], label: str) -> None:
    seen: set[tuple] = set()
    for item in items:
        identity = tuple(getattr(item, key) for key in keys)
        if identity in seen:
            raise RulePackError(f"{label}标识重复：{identity}")
        seen.add(identity)


def _check_rule_references(rules: list[RuleSpec], indicator_ids: set[str]) -> None:
    for spec in rules:
        if spec.indicator_id not in indicator_ids:
            raise RulePackError(
                f"规则 {spec.rule_id} 引用了不存在的指标项 {spec.indicator_id!r}"
            )


def _check_severity_conflicts(rules: list[RuleSpec]) -> None:
    severity_by_rule: dict[str, str | None] = {}
    for spec in rules:
        severity = spec.severity
        if spec.rule_id in severity_by_rule and severity_by_rule[spec.rule_id] != severity:
            raise RulePackError(f"规则 {spec.rule_id} 同时声明了不同等级")
        severity_by_rule[spec.rule_id] = severity
