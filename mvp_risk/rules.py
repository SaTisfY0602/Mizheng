"""基于已准入证据的风险规则。

每条规则都是**纯函数**：只读准入事实与缺口，不重新解析材料、不修改证据、不产生
新事实。规则返回 :class:`RiskDraft`（没有 ID 的草稿），由 ``RiskEngine`` 统一分配
ID 并组装成 :class:`RiskFinding`。

判定口径刻意与 ``mvp_decision`` 分开：
* ``Decision`` 回答「这个对象是否符合该项要求」；
* ``RiskFinding`` 回答「这里有什么风险、依据是什么、怎么整改」。

弱算法/弱协议名单与阈值**不再硬编码在本文件**，而是来自版本化规则包
``mvp_rules/data/rules_risk.json``：规则函数只负责求值，名单、阈值与等级通过
:func:`_rules` / :func:`_severity` 从 :func:`mvp_rules.default_rule_set` 读取。
这样规则版本可回溯到具体实验，也保证判定侧与风险侧用的是同一份阈值。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from mvp_contracts.models import AdmittedFact, EvidenceSnapshot
from mvp_rules import RuleSet, default_rule_set

from .findings import RiskSeverity

BINDING = "service_uses_certificate"
CERTIFICATE_NOT_AFTER = "certificate_not_after"
CERTIFICATE_NOT_BEFORE = "certificate_not_before"
CERTIFICATE_SUBJECT = "certificate_subject"
CERTIFICATE_ISSUER = "certificate_issuer"
CERTIFICATE_SAN_DNS = "certificate_san_dns"
CERTIFICATE_IS_SELF_SIGNED = "certificate_is_self_signed"
CERTIFICATE_IS_CA = "certificate_is_ca"
CERTIFICATE_SIGNATURE_ALGORITHM = "certificate_signature_algorithm"
CERTIFICATE_PUBLIC_KEY_ALGORITHM = "certificate_public_key_algorithm"
CERTIFICATE_PUBLIC_KEY_SIZE = "certificate_public_key_size"
CERTIFICATE_KEY_USAGE = "certificate_key_usage"
CERTIFICATE_EXTENDED_KEY_USAGE = "certificate_extended_key_usage"
CONFIGURED_TLS_PROTOCOLS = "configured_tls_protocols"
CONFIGURED_CIPHER_SUITES = "configured_cipher_suites"
CONFIGURED_SERVER_NAME = "configured_server_name"

SERVER_AUTH = "serverAuth"

# 规则包中记录的 severity 是 JSON 字符串，这里显式映射回枚举，缺项即报错，
# 避免从外部数据里静默拿到一个非法等级。
_SEVERITY_BY_NAME: dict[str, RiskSeverity] = {
    "HIGH": RiskSeverity.HIGH,
    "MEDIUM": RiskSeverity.MEDIUM,
    "LOW": RiskSeverity.LOW,
}


def _rules() -> RuleSet:
    return default_rule_set()


def _severity(rule_id: str) -> RiskSeverity:
    """取规则等级；规则包里的名字必须能映射到枚举，否则显式失败。"""
    name = _rules().severity_of(rule_id)
    try:
        return _SEVERITY_BY_NAME[name]
    except KeyError as exc:  # pragma: no cover - 规则包校验已挡在前面
        raise KeyError(f"规则 {rule_id!r} 声明了未知等级 {name!r}") from exc


@dataclass(frozen=True)
class RiskDraft:
    """尚未分配 ID 的风险项。"""

    rule_id: str
    severity: RiskSeverity
    object_id: str | None
    title: str
    description: str
    evidence_fact_ids: tuple[str, ...]
    remediation: str


def certificate_time_risks(
    snapshot: EvidenceSnapshot, *, expiring_days: int | None = None
) -> list[RiskDraft]:
    """证书已过期、即将到期，或到期时间无法确认/解析。

    ``expiring_days`` 缺省时取规则包 ``RISK-CERT-EXPIRING`` 的 ``expiring_days``
    参数；显式传入只用于测试构造边界场景。
    """
    if expiring_days is None:
        expiring_days = _rules().int_param("RISK-CERT-EXPIRING", "expiring_days")
    drafts: list[RiskDraft] = []
    certificates = _certificate_facts(snapshot.admitted_facts)

    for object_id, certificate_id, binding_fact_id in _bound_bindings(
        snapshot.admitted_facts
    ):
        fact = certificates.get(certificate_id, {}).get(CERTIFICATE_NOT_AFTER)
        if fact is None:
            drafts.append(
                RiskDraft(
                    rule_id="RISK-CERT-TIME-MISSING",
                    severity=_severity("RISK-CERT-TIME-MISSING"),
                    object_id=object_id,
                    title="无法确认证书有效期",
                    description=(
                        f"对象 {object_id} 已确认使用证书 {certificate_id}，"
                        "但缺少可用的到期时间事实，无法判断证书是否在有效期内。"
                    ),
                    evidence_fact_ids=(binding_fact_id,),
                    remediation="补充该证书的完整证书文件或证书链，使到期时间可被解析。",
                )
            )
            continue

        try:
            not_after = _parse_utc(str(fact.value))
        except ValueError:
            drafts.append(
                RiskDraft(
                    rule_id="RISK-CERT-TIME-UNPARSABLE",
                    severity=_severity("RISK-CERT-TIME-UNPARSABLE"),
                    object_id=object_id,
                    title="证书到期时间无法解析",
                    description=(
                        f"证书 {certificate_id} 的到期时间事实值为 {fact.value!r}，"
                        "不是带 UTC 时区的时刻，无法判断有效期。"
                    ),
                    evidence_fact_ids=(fact.id, binding_fact_id),
                    remediation="以标准格式重新提供证书到期时间（UTC，例 2026-12-31T23:59:59Z）。",
                )
            )
            continue

        remaining = not_after - snapshot.evaluation_time
        if remaining <= timedelta(0):
            drafts.append(
                RiskDraft(
                    rule_id="RISK-CERT-EXPIRED",
                    severity=_severity("RISK-CERT-EXPIRED"),
                    object_id=object_id,
                    title="证书已过期",
                    description=(
                        f"对象 {object_id} 使用的证书在核查时间 "
                        f"{_iso(snapshot.evaluation_time)} 已过期（到期 {_iso(not_after)}）。"
                    ),
                    evidence_fact_ids=(fact.id, binding_fact_id),
                    remediation="立即更换证书并重新绑定；同时核对证书链与自动续期配置是否生效。",
                )
            )
        elif remaining <= timedelta(days=expiring_days):
            drafts.append(
                RiskDraft(
                    rule_id="RISK-CERT-EXPIRING",
                    severity=_severity("RISK-CERT-EXPIRING"),
                    object_id=object_id,
                    title=f"证书将在 {expiring_days} 天内到期",
                    description=(
                        f"对象 {object_id} 使用的证书将于 {_iso(not_after)} 到期，"
                        f"距核查时间不足 {expiring_days} 天。"
                    ),
                    evidence_fact_ids=(fact.id, binding_fact_id),
                    remediation="提前安排证书更新与灰度发布，避免业务中断。",
                )
            )
    return drafts


def certificate_algorithm_risks(snapshot: EvidenceSnapshot) -> list[RiskDraft]:
    """弱签名算法、弱密钥长度、无法识别的算法。"""
    drafts: list[RiskDraft] = []
    certificates = _certificate_facts(snapshot.admitted_facts)

    for object_id, certificate_id, binding_fact_id in _bound_bindings(
        snapshot.admitted_facts
    ):
        facts = certificates.get(certificate_id, {})

        signature = facts.get(CERTIFICATE_SIGNATURE_ALGORITHM)
        if signature is not None:
            algorithm = str(signature.value)
            severity = _weak_signature_algorithms().get(algorithm)
            if severity is not None:
                drafts.append(
                    RiskDraft(
                        rule_id="RISK-CERT-WEAK-SIGNATURE",
                        severity=severity,
                        object_id=object_id,
                        title=f"证书使用弱签名算法：{algorithm}",
                        description=(
                            f"对象 {object_id} 使用的证书签名算法为 {algorithm}，"
                            "属于已不推荐用于新签发证书的算法。"
                        ),
                        evidence_fact_ids=(signature.id, binding_fact_id),
                        remediation="改用 SM2-with-SM3 或 SHA-256 及以上的签名算法重新签发证书。",
                    )
                )
            elif algorithm.startswith(
                _rule_param("RISK-CERT-SIGNATURE-UNKNOWN", "unknown_oid_prefix")
            ):
                drafts.append(
                    RiskDraft(
                        rule_id="RISK-CERT-SIGNATURE-UNKNOWN",
                        severity=_severity("RISK-CERT-SIGNATURE-UNKNOWN"),
                        object_id=object_id,
                        title="证书签名算法无法识别",
                        description=(
                            f"对象 {object_id} 使用的证书签名算法为 {algorithm}，"
                            "未被工具识别，无法判断是否满足要求。"
                        ),
                        evidence_fact_ids=(signature.id, binding_fact_id),
                        remediation="补充算法映射表或人工确认该算法的合规性。",
                    )
                )

        key_size = facts.get(CERTIFICATE_PUBLIC_KEY_SIZE)
        key_algorithm = facts.get(CERTIFICATE_PUBLIC_KEY_ALGORITHM)
        min_rsa_key_size = _rules().int_param("RISK-CERT-WEAK-KEY", "min_rsa_key_size")
        rsa_algorithm_name = _rule_param("RISK-CERT-WEAK-KEY", "rsa_algorithm_name")
        preferred_alternative = _rule_param("RISK-CERT-WEAK-KEY", "preferred_alternative")
        if key_size is not None and key_algorithm is not None:
            if (
                str(key_algorithm.value) == rsa_algorithm_name
                and int(key_size.value) < min_rsa_key_size
            ):
                drafts.append(
                    RiskDraft(
                        rule_id="RISK-CERT-WEAK-KEY",
                        severity=_severity("RISK-CERT-WEAK-KEY"),
                        object_id=object_id,
                        title=f"RSA 密钥长度不足：{key_size.value} 位",
                        description=(
                            f"对象 {object_id} 使用的证书为 RSA {key_size.value} 位，"
                            f"低于最低要求 {min_rsa_key_size} 位。"
                        ),
                        evidence_fact_ids=(key_size.id, binding_fact_id),
                        remediation=(
                            f"重新签发不小于 {min_rsa_key_size} 位的证书，"
                            f"或改用 {preferred_alternative} 证书。"
                        ),
                    )
                )
    return drafts


def transport_risks(snapshot: EvidenceSnapshot) -> list[RiskDraft]:
    """配置里启用/允许了弱协议版本或弱密码套件。"""
    drafts: list[RiskDraft] = []

    for object_id, facts in _facts_by_object(snapshot.admitted_facts).items():
        protocols = _last(facts, CONFIGURED_TLS_PROTOCOLS)
        if protocols is not None and isinstance(protocols.value, list):
            weak_protocols = set(
                _rules().str_tuple_param("RISK-TLS-WEAK-PROTOCOL", "weak_protocols")
            )
            weak = [item for item in protocols.value if item in weak_protocols]
            if weak:
                drafts.append(
                    RiskDraft(
                        rule_id="RISK-TLS-WEAK-PROTOCOL",
                        severity=_severity("RISK-TLS-WEAK-PROTOCOL"),
                        object_id=object_id,
                        title=f"启用了已废弃的 TLS 协议版本：{'、'.join(weak)}",
                        description=(
                            f"对象 {object_id} 的配置允许 {'、'.join(weak)}，"
                            "这些版本存在已知攻击面（如 POODLE、BEAST）。"
                        ),
                        evidence_fact_ids=(protocols.id,),
                        remediation="在 ssl_protocols 中仅保留 TLSv1.2 与 TLSv1.3。",
                    )
                )

        suites = _last(facts, CONFIGURED_CIPHER_SUITES)
        if suites is not None and isinstance(suites.value, list):
            # `!aNULL` 这类以 `!` 开头的是**排除**项，不能当成启用的弱套件
            markers = _rules().str_tuple_param("RISK-TLS-WEAK-CIPHER", "weak_cipher_markers")
            exclusion_prefix = _rule_param("RISK-TLS-WEAK-CIPHER", "exclusion_prefix")
            weak_suites = [
                item
                for item in suites.value
                if not item.startswith(exclusion_prefix)
                and any(marker in item.upper() for marker in markers)
            ]
            if weak_suites:
                drafts.append(
                    RiskDraft(
                        rule_id="RISK-TLS-WEAK-CIPHER",
                        severity=_severity("RISK-TLS-WEAK-CIPHER"),
                        object_id=object_id,
                        title="启用了弱密码套件",
                        description=(
                            f"对象 {object_id} 的 ssl_ciphers 包含弱套件："
                            f"{'、'.join(weak_suites)}。"
                        ),
                        evidence_fact_ids=(suites.id,),
                        remediation="移除 RC4、3DES、DES、NULL、EXPORT、MD5 等套件，保留国密套件或 ECDHE+AESGCM。",
                    )
                )
    return drafts


def binding_risks(snapshot: EvidenceSnapshot) -> list[RiskDraft]:
    """对象与证书的绑定无法确认——不是不安全，而是**无法评价**。"""
    drafts: list[RiskDraft] = []
    for gap in snapshot.gaps:
        if gap.target_condition != "binding":
            continue
        drafts.append(
            RiskDraft(
                rule_id="RISK-BINDING-UNKNOWN",
                severity=_severity("RISK-BINDING-UNKNOWN"),
                object_id=gap.scope.asset_id,
                title="服务与证书的绑定未确认",
                description=(
                    f"{gap.description}；在绑定确认前，该对象的证书合规性无法评价。"
                ),
                evidence_fact_ids=(),
                remediation="补充绑定记录（配置、握手抓包或人工确认），然后重新判断受影响对象。",
            )
        )
    return drafts


def certificate_validity_risks(snapshot: EvidenceSnapshot) -> list[RiskDraft]:
    """证书尚未生效（生效时间晚于核查时间）。"""
    drafts: list[RiskDraft] = []
    certificates = _certificate_facts(snapshot.admitted_facts)

    for object_id, certificate_id, binding_fact_id in _bound_bindings(
        snapshot.admitted_facts
    ):
        fact = certificates.get(certificate_id, {}).get(CERTIFICATE_NOT_BEFORE)
        if fact is None:
            continue
        try:
            not_before = _parse_utc(str(fact.value))
        except ValueError:
            continue
        if not_before > snapshot.evaluation_time:
            drafts.append(
                RiskDraft(
                    rule_id="RISK-CERT-NOT-YET-VALID",
                    severity=_severity("RISK-CERT-NOT-YET-VALID"),
                    object_id=object_id,
                    title="证书尚未生效",
                    description=(
                        f"对象 {object_id} 使用的证书生效时间为 {_iso(not_before)}，"
                        f"晚于核查时间 {_iso(snapshot.evaluation_time)}。"
                    ),
                    evidence_fact_ids=(fact.id, binding_fact_id),
                    remediation="核对系统时间与证书生效时间；投入使用前先更换为已生效的证书。",
                )
            )
    return drafts


def certificate_trust_risks(snapshot: EvidenceSnapshot) -> list[RiskDraft]:
    """自签证书用于服务，或签发者证书未随材料提供。"""
    drafts: list[RiskDraft] = []
    certificates = _certificate_facts(snapshot.admitted_facts)
    known_subjects = {
        str(candidate.value)
        for candidate in snapshot.candidates
        if candidate.predicate == CERTIFICATE_SUBJECT
    }

    for object_id, certificate_id, binding_fact_id in _bound_bindings(
        snapshot.admitted_facts
    ):
        facts = certificates.get(certificate_id, {})

        self_signed = facts.get(CERTIFICATE_IS_SELF_SIGNED)
        if self_signed is not None and self_signed.value is True:
            drafts.append(
                RiskDraft(
                    rule_id="RISK-CERT-SELF-SIGNED",
                    severity=_severity("RISK-CERT-SELF-SIGNED"),
                    object_id=object_id,
                    title="服务使用了自签证书",
                    description=(
                        f"对象 {object_id} 使用的证书签发者与主体相同（自签），"
                        "客户端无法通过受信任的信任锚验证其身份。"
                    ),
                    evidence_fact_ids=(self_signed.id, binding_fact_id),
                    remediation="由受信任的 CA 重新签发证书，并部署完整证书链。",
                )
            )
            # 自签时签发者就是自己，再报「签发者缺失」没有意义
            continue

        issuer = facts.get(CERTIFICATE_ISSUER)
        if issuer is not None and str(issuer.value) not in known_subjects:
            drafts.append(
                RiskDraft(
                    rule_id="RISK-CERT-UNTRUSTED-ISSUER",
                    severity=_severity("RISK-CERT-UNTRUSTED-ISSUER"),
                    object_id=object_id,
                    title="签发者证书未提供，信任链无法验证",
                    description=(
                        f"对象 {object_id} 使用的证书由 {issuer.value} 签发，"
                        "但本次材料中没有该签发者的证书，无法构建信任链。"
                    ),
                    evidence_fact_ids=(issuer.id, binding_fact_id),
                    remediation="补充签发者与中间 CA 证书，形成完整证书链后再核验。",
                )
            )
    return drafts


def certificate_purpose_risks(snapshot: EvidenceSnapshot) -> list[RiskDraft]:
    """证书缺少用途约束，或用途未包含 serverAuth。"""
    drafts: list[RiskDraft] = []
    certificates = _certificate_facts(snapshot.admitted_facts)
    required_eku = _rule_param("RISK-CERT-EKU-NOT-SERVER-AUTH", "required_eku")

    for object_id, certificate_id, binding_fact_id in _bound_bindings(
        snapshot.admitted_facts
    ):
        facts = certificates.get(certificate_id, {})
        key_usage = facts.get(CERTIFICATE_KEY_USAGE)
        extended = facts.get(CERTIFICATE_EXTENDED_KEY_USAGE)

        if key_usage is None or extended is None:
            evidence = tuple(
                fact.id
                for fact in (key_usage, extended, facts.get(CERTIFICATE_IS_CA))
                if fact is not None
            ) + (binding_fact_id,)
            drafts.append(
                RiskDraft(
                    rule_id="RISK-CERT-PURPOSE-MISSING",
                    severity=_severity("RISK-CERT-PURPOSE-MISSING"),
                    object_id=object_id,
                    title="证书未声明用途约束",
                    description=(
                        f"对象 {object_id} 使用的证书缺少 keyUsage 或 ExtendedKeyUsage 扩展，"
                        "无法确认它被限定用于服务端身份鉴别。"
                    ),
                    evidence_fact_ids=evidence,
                    remediation="重新签发带有 keyUsage（digitalSignature/keyEncipherment）与 "
                    "ExtendedKeyUsage（serverAuth）的证书。",
                )
            )
        elif required_eku not in [str(item) for item in extended.value]:
            drafts.append(
                RiskDraft(
                    rule_id="RISK-CERT-EKU-NOT-SERVER-AUTH",
                    severity=_severity("RISK-CERT-EKU-NOT-SERVER-AUTH"),
                    object_id=object_id,
                    title="证书用途未包含 serverAuth",
                    description=(
                        f"对象 {object_id} 使用的证书扩展密钥用途为 {extended.value}，"
                        f"不包含 {required_eku}，不应作为服务端证书使用。"
                    ),
                    evidence_fact_ids=(extended.id, binding_fact_id),
                    remediation=f"改用扩展密钥用途包含 {required_eku} 的证书。",
                )
            )
    return drafts


def certificate_name_risks(snapshot: EvidenceSnapshot) -> list[RiskDraft]:
    """证书 SAN 与配置里的 server_name 不匹配。"""
    drafts: list[RiskDraft] = []
    certificates = _certificate_facts(snapshot.admitted_facts)

    for object_id, facts in _facts_by_object(snapshot.admitted_facts).items():
        server_name_fact = _last(facts, CONFIGURED_SERVER_NAME)
        binding_fact = _last(facts, BINDING)
        if server_name_fact is None or not isinstance(server_name_fact.value, list):
            continue
        if binding_fact is None or not isinstance(binding_fact.value, str):
            continue

        san_fact = certificates.get(binding_fact.value, {}).get(CERTIFICATE_SAN_DNS)
        if san_fact is None or not isinstance(san_fact.value, list):
            continue

        san_entries = [str(entry) for entry in san_fact.value]
        wildcard_prefix = _rule_param("RISK-CERT-SAN-MISMATCH", "wildcard_prefix")
        unmatched = [
            str(name)
            for name in server_name_fact.value
            if not any(
                _name_matches(str(name), entry, wildcard_prefix=wildcard_prefix)
                for entry in san_entries
            )
        ]
        if unmatched:
            drafts.append(
                RiskDraft(
                    rule_id="RISK-CERT-SAN-MISMATCH",
                    severity=_severity("RISK-CERT-SAN-MISMATCH"),
                    object_id=object_id,
                    title="证书域名与配置的服务名不匹配",
                    description=(
                        f"对象 {object_id} 配置的 server_name 为 {unmatched}，"
                        f"但证书 SAN 只有 {san_entries}，客户端会因域名校验失败而拒绝连接。"
                    ),
                    evidence_fact_ids=(server_name_fact.id, san_fact.id, binding_fact.id),
                    remediation="为该域名重新签发证书，或在配置中改用与证书 SAN 一致的域名。",
                )
            )
    return drafts


# --------------------------------------------------------------------------- 辅助


def _rule_param(rule_id: str, name: str) -> str:
    """取规则包中的字符串参数；缺参显式失败，不用隐式默认值兜底。"""
    value = _rules().param(rule_id, name)
    if not isinstance(value, str):
        raise TypeError(f"规则 {rule_id!r} 的参数 {name!r} 必须是字符串，实际为 {value!r}")
    return value


def _weak_signature_algorithms() -> dict[str, RiskSeverity]:
    """弱签名算法 → 等级；名单与等级都来自规则包。"""
    mapping = _rules().mapping_param("RISK-CERT-WEAK-SIGNATURE", "weak_signature_algorithms")
    result: dict[str, RiskSeverity] = {}
    for algorithm, severity_name in mapping.items():
        try:
            result[algorithm] = _SEVERITY_BY_NAME[severity_name]
        except KeyError as exc:  # pragma: no cover - 规则包校验已挡在前面
            raise KeyError(
                f"规则 RISK-CERT-WEAK-SIGNATURE 为 {algorithm!r} 声明了未知等级 {severity_name!r}"
            ) from exc
    return result


def _facts_by_object(facts: list[AdmittedFact]) -> dict[str, list[AdmittedFact]]:
    grouped: dict[str, list[AdmittedFact]] = {}
    for fact in facts:
        asset_id = fact.scope.asset_id
        if asset_id is None:
            continue
        grouped.setdefault(asset_id, []).append(fact)
    return grouped


def _last(facts: list[AdmittedFact], predicate: str) -> AdmittedFact | None:
    matched = [fact for fact in facts if fact.predicate == predicate]
    return matched[-1] if matched else None


def _bound_bindings(facts: list[AdmittedFact]) -> list[tuple[str, str, str]]:
    """返回 ``(对象, 证书材料 ID, 绑定事实 ID)``，按事实顺序稳定。"""
    bindings: list[tuple[str, str, str]] = []
    for fact in facts:
        if fact.predicate != BINDING or not isinstance(fact.value, str):
            continue
        asset_id = fact.scope.asset_id
        if asset_id is None:
            continue
        bindings.append((asset_id, fact.value, fact.id))
    return bindings


def _certificate_facts(facts: list[AdmittedFact]) -> dict[str, dict[str, AdmittedFact]]:
    """证书材料 ID → {谓词: 事实}；同名谓词取最后一条。"""
    grouped: dict[str, dict[str, AdmittedFact]] = {}
    for fact in facts:
        if not fact.predicate.startswith("certificate_"):
            continue
        grouped.setdefault(fact.artifact_id, {})[fact.predicate] = fact
    return grouped


def _name_matches(server_name: str, san_entry: str, *, wildcard_prefix: str = "*.") -> bool:
    """域名匹配：支持精确匹配与单层通配符 ``*.example.cn``。

    ``wildcard_prefix`` 来自规则包 ``RISK-CERT-SAN-MISMATCH`` 的参数，避免把
    通配符写法硬编码在求值函数里。
    """
    if server_name == san_entry:
        return True
    if san_entry.startswith(wildcard_prefix):
        suffix = san_entry[len(wildcard_prefix) - 1 :]
        return server_name.endswith(suffix) and server_name.count(
            "."
        ) == san_entry.count(".")
    return False


def _parse_utc(text: str) -> datetime:
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"时间必须带 UTC 时区：{text!r}")
    return parsed.astimezone(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")
