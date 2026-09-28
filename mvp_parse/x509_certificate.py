"""X.509 证书解析器：把证书字段提取为共享契约的候选事实。

字段提取逻辑改写自成员一交付的 ``member1_parser.py``（见 `复赛/member 1/`），并修正
三处与他自造契约绑定的写法：

* ``storage_key`` 经 ``mvp_flow.storage.MaterialStore`` 解析，不再对调用方给的路径直接
  ``open()``（协作规范 §4）；
* 候选 ID 由注入的 ``IdAllocator`` 分配，不再用 ``uuid4``（协作规范 §3.6）；
* 参考时间直接用 ``ParseRequest.scope.as_of``，不读执行当天时间（协作规范 §3.5）。

每个字段都带 ``CERT_FIELD`` 来源锚点，因此「每条重要信息都能找到原始来源」。
"""

from __future__ import annotations

from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from mvp_contracts.interfaces import IdAllocator
from mvp_contracts.models import (
    AnchorKind,
    CandidateFact,
    ErrorItem,
    EvidenceLevel,
    ParseRequest,
    ParseResult,
    ParseStatus,
    SourceAnchor,
)

from mvp_flow.storage import MaterialStorageError, MaterialStore

E_PARSE_FAILED = "E_PARSE_FAILED"
PARSE_STAGE = "PARSE"
CANDIDATE_PREFIX = "CAND"
QUOTE_LIMIT = 200

CERTIFICATE_NOT_AFTER = "certificate_not_after"
CERTIFICATE_NOT_BEFORE = "certificate_not_before"
CERTIFICATE_IS_SELF_SIGNED = "certificate_is_self_signed"
CERTIFICATE_IS_CA = "certificate_is_ca"
CERTIFICATE_KEY_USAGE = "certificate_key_usage"
CERTIFICATE_EXTENDED_KEY_USAGE = "certificate_extended_key_usage"

# X.509 扩展的 keyUsage 位名（与 cryptography 的 KeyUsage 属性一一对应）
_KEY_USAGE_BITS = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
)

# 扩展密钥用途 OID → 名称
_EXTENDED_KEY_USAGE_NAMES = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "ocspSigning",
}

# 签名算法 OID → 名称；SM2-with-SM3 沿用成员一交付的映射
SIGNATURE_ALGORITHM_NAMES = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.156.10197.1.501": "sm2-with-sm3",
}


class X509CertificateParser:
    """实现 ``mvp_contracts.interfaces.Parser``：``parse(ParseRequest) -> ParseResult``。"""

    def __init__(
        self,
        *,
        store: MaterialStore,
        id_allocator: IdAllocator,
        parser_version: str = "x509-0.2.0",
    ) -> None:
        self._store = store
        self._id_allocator = id_allocator
        self._parser_version = parser_version

    def parse(self, request: ParseRequest) -> ParseResult:
        artifact = request.artifact
        try:
            data = self._read(artifact)
            certificate = self._load(data, artifact.format)
        except MaterialStorageError as exc:
            return _failed(artifact.id, f"受控存储无法提供材料：{exc}")
        except Exception as exc:  # 证书损坏或格式与声明不符
            return _failed(artifact.id, f"{type(exc).__name__}: {exc}")

        candidates = [
            self._candidate(request, field_path, predicate, value)
            for field_path, predicate, value in _field_values(certificate)
        ]
        return ParseResult(
            artifact_id=artifact.id,
            status=ParseStatus.SUCCEEDED,
            coverage="COMPLETE",
            candidates=candidates,
            errors=[],
        )

    def _read(self, artifact) -> bytes:
        return self._store.resolve(artifact.storage_key).read_bytes()

    @staticmethod
    def _load(data: bytes, artifact_format: str) -> x509.Certificate:
        if artifact_format == "X509_PEM":
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)

    def _candidate(
        self, request: ParseRequest, field_path: str, predicate: str, value
    ) -> CandidateFact:
        artifact_id = request.artifact.id
        return CandidateFact(
            id=self._id_allocator.allocate(
                prefix=CANDIDATE_PREFIX, project_id=request.scope.project_id
            ),
            artifact_id=artifact_id,
            anchor=SourceAnchor(
                artifact_id=artifact_id,
                kind=AnchorKind.CERT_FIELD,
                quote=_quote_of(value),
                field_path=field_path,
            ),
            predicate=predicate,
            value=value,
            scope=request.scope,
            evidence_level=EvidenceLevel.CERTIFICATE,
            parser_version=self._parser_version,
        )


def _field_values(certificate: x509.Certificate) -> list[tuple[str, str, object]]:
    """返回 ``(field_path, predicate, value)`` 列表，保持稳定顺序。"""
    specs: list[tuple[str, str, object]] = [
        ("validity.not_after", CERTIFICATE_NOT_AFTER, _iso(certificate.not_valid_after_utc)),
        ("validity.not_before", CERTIFICATE_NOT_BEFORE, _iso(certificate.not_valid_before_utc)),
        ("serial_number", "certificate_serial_number", format(certificate.serial_number, "x")),
        ("subject", "certificate_subject", certificate.subject.rfc4514_string()),
        ("issuer", "certificate_issuer", certificate.issuer.rfc4514_string()),
        ("signature_algorithm", "certificate_signature_algorithm", _signature_algorithm(certificate)),
        ("public_key_algorithm", "certificate_public_key_algorithm", _public_key_algorithm(certificate)),
        ("subject_issuer_relation", CERTIFICATE_IS_SELF_SIGNED, _is_self_signed(certificate)),
        ("extensions.basic_constraints", CERTIFICATE_IS_CA, _is_ca(certificate)),
    ]
    key_size = _public_key_size(certificate)
    if key_size is not None:
        specs.append(("public_key.key_size", "certificate_public_key_size", key_size))
    san = _subject_alternative_names(certificate)
    if san:
        specs.append(("extensions.subject_alternative_name", "certificate_san_dns", san))
    # 用途扩展不存在时**不产生候选**：让风险规则能区分「没声明用途」和「声明了空用途」
    key_usage = _key_usage(certificate)
    if key_usage:
        specs.append(("extensions.key_usage", CERTIFICATE_KEY_USAGE, key_usage))
    extended_key_usage = _extended_key_usage(certificate)
    if extended_key_usage:
        specs.append(
            (
                "extensions.extended_key_usage",
                CERTIFICATE_EXTENDED_KEY_USAGE,
                extended_key_usage,
            )
        )
    return specs


def _iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def _signature_algorithm(certificate: x509.Certificate) -> str:
    # cryptography 的实际属性是 signature_algorithm_oid；成员一交付的
    # ``signature_algorithm_identifier`` 在该库上并不存在（那段代码没跑通过）。
    oid = certificate.signature_algorithm_oid.dotted_string
    return SIGNATURE_ALGORITHM_NAMES.get(oid, f"unknown_oid:{oid}")


def _public_key_algorithm(certificate: x509.Certificate) -> str:
    key = certificate.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSAPublicKey"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EllipticCurvePublicKey"
    return type(key).__name__


def _public_key_size(certificate: x509.Certificate) -> int | None:
    key = certificate.public_key()
    if isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        return key.key_size
    return None


def _subject_alternative_names(certificate: x509.Certificate) -> list[str]:
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound:
        return []
    return [str(name.value) for name in extension.value]


def _is_self_signed(certificate: x509.Certificate) -> bool:
    """签发者与主体完全相同即视为自签（信任链的根，不能直接作为服务证书信任）。"""
    return certificate.subject == certificate.issuer


def _is_ca(certificate: x509.Certificate) -> bool:
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
    except x509.ExtensionNotFound:
        return False
    return bool(extension.value.ca)


def _key_usage(certificate: x509.Certificate) -> list[str]:
    try:
        extension = certificate.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound:
        return []
    return [bit for bit in _KEY_USAGE_BITS if getattr(extension.value, bit)]


def _extended_key_usage(certificate: x509.Certificate) -> list[str]:
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        )
    except x509.ExtensionNotFound:
        return []
    return [
        _EXTENDED_KEY_USAGE_NAMES.get(oid.dotted_string, oid.dotted_string)
        for oid in extension.value
    ]


def _quote_of(value: object) -> str:
    text = value if isinstance(value, str) else str(value)
    return text[:QUOTE_LIMIT]


def _failed(artifact_id: str, message: str) -> ParseResult:
    return ParseResult(
        artifact_id=artifact_id,
        status=ParseStatus.FAILED,
        coverage="UNKNOWN",
        candidates=[],
        errors=[
            ErrorItem(
                code=E_PARSE_FAILED,
                stage=PARSE_STAGE,
                artifact_id=artifact_id,
                message=message,
            )
        ],
    )
