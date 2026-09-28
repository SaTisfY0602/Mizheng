"""版本化规则包测试：加载、静态校验、与代码实现的对账。

规则包是本阶段新增的「内容库」，它把此前散落在代码里的名单与阈值集中成带版本的
数据文件。这些测试只断言两件事：

1. **数据本身自洽**——引用、重复、层级、单元编号、版本一致性都在加载时校验；
2. **数据与代码一致**——规则包声明了哪些规则，代码就必须真的实现哪些规则，
   不允许任何一侧静默漂移。
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from mvp_decision import RULE_REGISTRY
from mvp_risk import RISK_RULE_IDS, RiskEngine
from mvp_rules import (
    DATA_DIR,
    LAYERS,
    TOOL_UNITS,
    RulePackError,
    RuleSet,
    default_rule_set,
    load_rule_set,
    rule_pack_sm3,
)

ROOT = Path(__file__).resolve().parents[1]


def _minimal_pack(*, meta_extra: dict | None = None, rules: list[dict] | None = None) -> dict:
    """一个最小合法规则包：一条指标 + 一条规则。"""
    meta = {
        "id": "RP-TEST",
        "version": "1.0.0",
        "schema": "mvp-rules-1",
        "description": "测试用最小规则包",
        "created_at": "2026-09-28T00:00:00Z",
    }
    if meta_extra:
        meta.update(meta_extra)
    default_rule = {
        "rule_id": "TEST-RULE-1",
        "title": "测试规则",
        "layer": "RISK",
        "indicator_id": "TEST-IND-1",
        "tool_unit": "U01",
        "evaluation": "自动",
    }
    return {
        "meta": meta,
        "indicators": [
            {
                "indicator_id": "TEST-IND-1",
                "standard": "GB/T 39786-2021",
                "clause": "8.1 a)",
                "title": "测试指标",
                "domain": "测试域",
                "level_clauses": {"1": "6.1 a) 可", "2": "7.1 a) 宜"},
            }
        ],
        "rules": rules if rules is not None else [default_rule],
    }


def _write_pack(directory: Path, payload: dict, name: str = "pack.json") -> Path:
    path = directory / name
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


class DefaultRulePackTest(unittest.TestCase):
    """随代码分发的规则包必须能加载，且关键口径与既有实现一致。"""

    def test_default_pack_loads_with_expected_identity(self):
        rule_set = default_rule_set()

        self.assertEqual(rule_set.meta.id, "RP-CRYPTO-ASSESS")
        self.assertEqual(rule_set.meta.version, "0.3.0-mvp")
        self.assertEqual(rule_set.meta.schema, "mvp-rules-1")

    def test_pack_declares_all_implemented_risk_rules(self):
        rule_set = default_rule_set()

        declared = set(rule_set.rule_ids(layer="RISK"))
        self.assertEqual(declared, set(RISK_RULE_IDS))

    def test_pack_declares_all_registered_decision_rules(self):
        rule_set = default_rule_set()

        declared = set(rule_set.rule_ids(layer="DECISION"))
        # DEMO-BIND-TIME 是 DEC-BIND-TIME 的旧别名，不需要在清单里各写一遍。
        implemented = {
            rule_id
            for rule_id in RULE_REGISTRY
            if rule_id != "DEMO-BIND-TIME"
        }
        self.assertEqual(declared, implemented)

    def test_risk_rule_ids_match_rule_id_literals_in_source(self):
        """RISK_RULE_IDS 必须与 mvp_risk/rules.py 里出现的 rule_id 字面量一致。"""
        source = (ROOT / "mvp_risk" / "rules.py").read_text(encoding="utf-8")
        literals = set(re.findall(r'rule_id="(RISK-[A-Z0-9-]+)"', source))

        self.assertEqual(literals, set(RISK_RULE_IDS))

    def test_pack_preserves_existing_thresholds(self):
        """迁移不能悄悄改口径：这些值此前硬编码在 mvp_risk/rules.py 里。"""
        rule_set = default_rule_set()

        self.assertEqual(
            rule_set.str_tuple_param("RISK-TLS-WEAK-PROTOCOL", "weak_protocols"),
            ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"),
        )
        self.assertEqual(
            rule_set.str_tuple_param("RISK-TLS-WEAK-CIPHER", "weak_cipher_markers"),
            ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "anon", "ADH"),
        )
        self.assertEqual(
            rule_set.mapping_param("RISK-CERT-WEAK-SIGNATURE", "weak_signature_algorithms"),
            {
                "sha1WithRSAEncryption": "HIGH",
                "md5WithRSAEncryption": "HIGH",
                "ecdsa-with-SHA1": "HIGH",
            },
        )
        self.assertEqual(rule_set.int_param("RISK-CERT-WEAK-KEY", "min_rsa_key_size"), 2048)
        self.assertEqual(rule_set.int_param("RISK-CERT-EXPIRING", "expiring_days"), 30)

    def test_engine_default_expiring_days_comes_from_pack(self):
        """风险引擎缺省的临期天数取规则包，而不是代码里的常量。"""
        expected = default_rule_set().int_param("RISK-CERT-EXPIRING", "expiring_days")

        source = (ROOT / "mvp_risk" / "engine.py").read_text(encoding="utf-8")
        self.assertIn('int_param(EXPIRING_RULE_ID, "expiring_days")', source)
        self.assertNotIn("DEFAULT_EXPIRING_DAYS", source)
        self.assertEqual(expected, 30)

    def test_pack_sm3_is_stable_and_hex(self):
        rule_set = default_rule_set()

        first = rule_pack_sm3(rule_set)
        second = rule_pack_sm3(rule_set)

        self.assertEqual(first, second)
        self.assertRegex(first, r"^[0-9a-f]{64}$")

    def test_pack_sm3_changes_when_rule_content_changes(self):
        """规则文件被改动时摘要必须变——这正是核验端要能发现的事情。"""
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _write_pack(directory, _minimal_pack())
            before = rule_pack_sm3(load_rule_set(directory))

            changed = _minimal_pack()
            changed["rules"][0]["title"] = "改过的标题"
            _write_pack(directory, changed)
            after = rule_pack_sm3(load_rule_set(directory))

            self.assertNotEqual(before, after)

    def test_indicator_catalog_covers_all_eight_areas(self):
        """GB/T 39786-2021 每级下有 8 个子节，目录要覆盖全部 8 个域。"""
        rule_set = default_rule_set()

        domains = {indicator.domain for indicator in rule_set.indicators}
        self.assertEqual(
            domains,
            {
                "物理和环境安全",
                "网络和通信安全",
                "设备和计算安全",
                "应用和数据安全",
                "管理制度",
                "人员管理",
                "建设运行",
                "应急处置",
            },
        )
        # 未接入的域也要如实留在目录里，不能因为「没自动规则」就删掉
        self.assertTrue(any(not item.automated for item in rule_set.indicators))
        self.assertTrue(any(item.automated for item in rule_set.indicators))

    def test_indicator_and_rule_mapping_is_bidirectional(self):
        """指标声明与规则声明必须完全对上，且每条规则只归属一个指标。

        只查一个方向会漏掉「重复挂在两个指标下」和「规则没被任何指标覆盖」两种
        漂移，所以这里两个方向都查，并额外断言归属唯一。
        """
        rule_set = default_rule_set()

        claimed: dict[str, str] = {}
        for indicator in rule_set.indicators:
            for rule_id in indicator.automated_rule_ids:
                with self.subTest(indicator=indicator.indicator_id, rule_id=rule_id):
                    spec = rule_set.rule(rule_id)
                    self.assertEqual(
                        spec.indicator_id,
                        indicator.indicator_id,
                        f"{rule_id} 的指标与 {indicator.indicator_id} 的声明不一致",
                    )
                    self.assertNotIn(
                        rule_id,
                        claimed,
                        f"{rule_id} 被多个指标重复声明：{claimed.get(rule_id)} 与 "
                        f"{indicator.indicator_id}",
                    )
                    claimed[rule_id] = indicator.indicator_id

        # 反方向：每条自动规则都必须被某个指标覆盖
        for spec in rule_set.rules:
            with self.subTest(rule_id=spec.rule_id):
                self.assertIn(
                    spec.rule_id,
                    claimed,
                    f"规则 {spec.rule_id} 没有被任何指标目录项覆盖",
                )

    def test_clause_numbers_follow_the_standard_layout(self):
        """条款号必须落在 GB/T 39786-2021 的实际结构上。

        正文第 6—10 章依次是第一级到第五级，每级下 8 个子节。目录的 clause 指向
        **第三级（第 8 章）**，形如 ``8.2 a)``；level_clauses 记录各级条款。
        """
        rule_set = default_rule_set()

        for indicator in rule_set.indicators:
            with self.subTest(indicator=indicator.indicator_id):
                self.assertRegex(
                    indicator.clause,
                    r"^8\.[1-8] [a-z]\)$",
                    "clause 必须指向第三级（第 8 章）的具体条款",
                )
                self.assertTrue(indicator.level_clauses, "必须记录各级条款")

    def test_level_clauses_keys_match_declared_levels(self):
        """level_clauses 的等级键必须与 levels 完全一致，不能各说各话。"""
        rule_set = default_rule_set()

        for indicator in rule_set.indicators:
            with self.subTest(indicator=indicator.indicator_id):
                declared = {str(level) for level in indicator.levels}
                self.assertEqual(set(indicator.level_clauses), declared)

    def test_level_clauses_point_into_the_right_level_chapter(self):
        """第 N 级的条款必须写在第 N+5 章：2 级→7、3 级→8、4 级→9。"""
        rule_set = default_rule_set()

        for indicator in rule_set.indicators:
            for level, clause in indicator.level_clauses.items():
                with self.subTest(indicator=indicator.indicator_id, level=level):
                    self.assertTrue(
                        clause.startswith(f"{int(level) + 5}."),
                        f"{level} 级的条款应写在第 {int(level) + 5} 章，实际 {clause!r}",
                    )

    def test_every_rule_reference_carries_a_real_clause(self):
        """每条规则的标准依据都要写到具体条款，而不是只写标准号。"""
        rule_set = default_rule_set()

        for spec in rule_set.rules:
            with self.subTest(rule_id=spec.rule_id):
                self.assertTrue(spec.standard_refs)
                for ref in spec.standard_refs:
                    self.assertRegex(
                        ref,
                        r"GB/T 39786-2021 8\.",
                        f"标准依据要落到第 8 章的具体条款：{ref!r}",
                    )


class RulePackLoaderTest(unittest.TestCase):
    """加载器的静态校验：宁可启动即失败，也不要让错引用悄悄进报告。"""

    def _load(self, payload: dict) -> RuleSet:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _write_pack(directory, payload)
            return load_rule_set(directory)

    def test_minimal_pack_loads(self):
        rule_set = self._load(_minimal_pack())

        self.assertEqual(rule_set.meta.version, "1.0.0")
        self.assertEqual(rule_set.rule_ids(), ("TEST-RULE-1",))

    def test_missing_directory_fails(self):
        with self.assertRaises(RulePackError):
            load_rule_set(Path(tempfile.gettempdir()) / "no-such-rule-pack-dir")

    def test_empty_directory_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RulePackError):
                load_rule_set(Path(tmp))

    def test_invalid_json_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "pack.json").write_text("{not json", encoding="utf-8")
            with self.assertRaises(RulePackError):
                load_rule_set(Path(tmp))

    def test_duplicate_rule_id_fails(self):
        payload = _minimal_pack()
        payload["rules"].append(dict(payload["rules"][0]))

        with self.assertRaises(RulePackError):
            self._load(payload)

    def test_rule_referencing_unknown_indicator_fails(self):
        payload = _minimal_pack()
        payload["rules"][0]["indicator_id"] = "NOT-EXIST"

        with self.assertRaises(RulePackError):
            self._load(payload)

    def test_unknown_tool_unit_fails(self):
        payload = _minimal_pack()
        payload["rules"][0]["tool_unit"] = "U99"

        with self.assertRaises(RulePackError):
            self._load(payload)

    def test_unknown_layer_fails(self):
        payload = _minimal_pack()
        payload["rules"][0]["layer"] = "GUESS"

        with self.assertRaises(RulePackError):
            self._load(payload)

    def test_missing_required_rule_field_fails(self):
        for field in ("title", "layer", "indicator_id", "tool_unit", "evaluation"):
            with self.subTest(field=field):
                payload = _minimal_pack()
                del payload["rules"][0][field]
                with self.assertRaises(RulePackError):
                    self._load(payload)

    def test_unknown_indicator_field_fails(self):
        payload = _minimal_pack()
        payload["indicators"][0]["unexpected"] = True

        with self.assertRaises(RulePackError):
            self._load(payload)

    def test_invalid_level_fails(self):
        payload = _minimal_pack()
        payload["indicators"][0]["levels"] = [0, 9]

        with self.assertRaises(RulePackError):
            self._load(payload)

    def test_rule_versions_referencing_unknown_rule_fails(self):
        payload = _minimal_pack(meta_extra={"rule_versions": {"1.0.0": ["NOT-IMPLEMENTED"]}})

        with self.assertRaises(RulePackError):
            self._load(payload)

    def test_inconsistent_versions_across_files_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _write_pack(directory, _minimal_pack(), name="a.json")
            second = _minimal_pack()
            second["meta"]["id"] = "RP-TEST-2"
            second["meta"]["version"] = "2.0.0"
            _write_pack(directory, second, name="b.json")

            with self.assertRaises(RulePackError):
                load_rule_set(directory)

    def test_rule_versions_map_is_exposed(self):
        payload = _minimal_pack(
            meta_extra={"supersedes": ["0.9.0"], "rule_versions": {"0.9.0": ["TEST-RULE-1"]}}
        )
        rule_set = self._load(payload)

        self.assertEqual(rule_set.rules_for_version("0.9.0"), ("TEST-RULE-1",))
        self.assertEqual(rule_set.accepted_versions, frozenset({"1.0.0", "0.9.0"}))

    def test_unknown_version_falls_back_to_all_decision_rules(self):
        rule_set = self._load(_minimal_pack())

        # 没有为某版本声明规则时，回退到「全部判定层规则」，而不是静默不跑
        self.assertEqual(rule_set.rules_for_version("9.9.9"), ())


class RuleSetQueryTest(unittest.TestCase):
    """``RuleSet`` 的查询接口：取不到就报错，绝不返回隐式默认值。"""

    def setUp(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _write_pack(directory, _minimal_pack())
            self.rule_set = load_rule_set(directory)

    def test_rule_lookup_raises_for_unknown_id(self):
        with self.assertRaises(KeyError):
            self.rule_set.rule("NO-SUCH-RULE")

    def test_has_rule(self):
        self.assertTrue(self.rule_set.has_rule("TEST-RULE-1"))
        self.assertFalse(self.rule_set.has_rule("NO-SUCH-RULE"))

    def test_indicator_lookup_raises_for_unknown_id(self):
        with self.assertRaises(KeyError):
            self.rule_set.indicator("NO-SUCH-INDICATOR")

    def test_severity_raises_when_rule_has_no_severity(self):
        # 最小规则没有 severity 参数：取等级必须失败，而不是给个默认等级
        with self.assertRaises(KeyError):
            self.rule_set.severity_of("TEST-RULE-1")

    def test_int_param_rejects_non_integer(self):
        rule_set = self._load_with_parameters({"severity": "HIGH", "count": "many"})
        with self.assertRaises(TypeError):
            rule_set.int_param("TEST-RULE-1", "count")

    def test_str_tuple_param_rejects_mixed_types(self):
        rule_set = self._load_with_parameters({"severity": "HIGH", "names": ["a", 1]})
        with self.assertRaises(TypeError):
            rule_set.str_tuple_param("TEST-RULE-1", "names")

    def test_missing_parameter_raises(self):
        with self.assertRaises(KeyError):
            self.rule_set.param("TEST-RULE-1", "absent")

    def _load_with_parameters(self, parameters: dict) -> RuleSet:
        payload = _minimal_pack()
        payload["rules"][0]["parameters"] = parameters
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _write_pack(directory, payload)
            return load_rule_set(directory)


class RuleSetInvariantsTest(unittest.TestCase):
    """对内存对象本身的不变式做检查，文档化 ``supersedes`` 的语义。"""

    def test_supersedes_extends_accepted_versions(self):
        rule_set = default_rule_set()

        self.assertIn("demo-0.2.0", rule_set.accepted_versions)
        self.assertIn(rule_set.meta.version, rule_set.accepted_versions)

    def test_historical_version_runs_the_subset_it_declares(self):
        """历史样例快照只带绑定与到期时间事实，就只跑它支持的那条规则。"""
        rule_set = default_rule_set()

        self.assertEqual(rule_set.rules_for_version("demo-0.2.0"), ("DEC-BIND-TIME",))
        self.assertEqual(
            rule_set.rules_for_version("0.3.0-mvp"),
            ("DEC-BIND-TIME", "DEC-CERT-KEY-STRENGTH", "DEC-CERT-KEY-USAGE"),
        )

    def test_every_declared_rule_has_standard_reference_and_test(self):
        """每条规则都要能回到标准依据与测试，否则规则版本无法回溯。"""
        rule_set = default_rule_set()

        for spec in rule_set.rules:
            with self.subTest(rule_id=spec.rule_id):
                self.assertTrue(spec.standard_refs, "规则必须写明标准依据")
                self.assertTrue(spec.tested_by, "规则必须写明由哪些测试覆盖")
                self.assertIn(spec.layer, LAYERS)
                self.assertIn(spec.tool_unit, TOOL_UNITS)

    def test_data_directory_is_the_default_source(self):
        self.assertEqual(default_rule_set().source_dir, DATA_DIR)


if __name__ == "__main__":
    unittest.main()
