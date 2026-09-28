"""Nginx 配置解析器：提取 `ssl_certificate` 路径、`ssl_protocols` 与 `ssl_ciphers`。

协作规范要求的最小路径之一是「读取一份 Nginx 配置中的 `ssl_certificate` 位置」；
二阶段起额外提取协议版本与密码套件，供风险规则判断弱协议、弱套件。

解析器只提出候选事实，不判断证书是否真的被该服务使用——那需要绑定确认。
同名指令出现多次时取**最后一次**（Nginx 语义是后者覆盖前者），避免同一对象上
出现多条相互矛盾的候选。
"""

from __future__ import annotations

import re

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
CONFIGURED_CERTIFICATE_PATH = "configured_certificate_path"
CONFIGURED_TLS_PROTOCOLS = "configured_tls_protocols"
CONFIGURED_CIPHER_SUITES = "configured_cipher_suites"
CONFIGURED_SERVER_NAME = "configured_server_name"

# 解析顺序固定，保证候选事实顺序稳定、可复现
_DIRECTIVE_ORDER = (
    CONFIGURED_SERVER_NAME,
    CONFIGURED_CERTIFICATE_PATH,
    CONFIGURED_TLS_PROTOCOLS,
    CONFIGURED_CIPHER_SUITES,
)

_SSL_CERTIFICATE = re.compile(
    r"""^\s*ssl_certificate\s+(?P<value>[^;]+);""", re.IGNORECASE
)
_SSL_PROTOCOLS = re.compile(
    r"""^\s*ssl_protocols\s+(?P<value>[^;]+);""", re.IGNORECASE
)
_SSL_CIPHERS = re.compile(
    r"""^\s*ssl_ciphers\s+(?P<value>[^;]+);""", re.IGNORECASE
)
_SERVER_NAME = re.compile(
    r"""^\s*server_name\s+(?P<value>[^;]+);""", re.IGNORECASE
)


class NginxConfigParser:
    """实现 ``mvp_contracts.interfaces.Parser``：``parse(ParseRequest) -> ParseResult``。"""

    def __init__(
        self,
        *,
        store: MaterialStore,
        id_allocator: IdAllocator,
        parser_version: str = "nginx-0.2.0",
    ) -> None:
        self._store = store
        self._id_allocator = id_allocator
        self._parser_version = parser_version

    def parse(self, request: ParseRequest) -> ParseResult:
        artifact = request.artifact
        try:
            text = self._read(artifact)
        except MaterialStorageError as exc:
            return _failed(artifact.id, f"受控存储无法提供材料：{exc}")
        except OSError as exc:
            return _failed(artifact.id, f"读取配置失败：{exc}")

        candidates = [
            self._candidate(request, line_number, quote, predicate, value)
            for line_number, quote, predicate, value in _extract_directives(text)
        ]
        return ParseResult(
            artifact_id=artifact.id,
            status=ParseStatus.SUCCEEDED,
            coverage="COMPLETE",
            candidates=candidates,
            errors=[],
        )

    def _read(self, artifact) -> str:
        path = self._store.resolve(artifact.storage_key)
        return path.read_text(encoding="utf-8", errors="replace")

    def _candidate(
        self,
        request: ParseRequest,
        line_number: int,
        quote: str,
        predicate: str,
        value: object,
    ) -> CandidateFact:
        artifact_id = request.artifact.id
        return CandidateFact(
            id=self._id_allocator.allocate(
                prefix=CANDIDATE_PREFIX, project_id=request.scope.project_id
            ),
            artifact_id=artifact_id,
            anchor=SourceAnchor(
                artifact_id=artifact_id,
                kind=AnchorKind.CONFIG_LINE,
                quote=quote,
                line_number=line_number,
            ),
            predicate=predicate,
            value=value,
            scope=request.scope,
            evidence_level=EvidenceLevel.CONFIGURED,
            parser_version=self._parser_version,
        )


def _extract_directives(text: str) -> list[tuple[int, str, str, object]]:
    """返回 ``(行号, 原始行, 谓词, 值)``；同名指令取最后一次出现。"""
    latest: dict[str, tuple[int, str, object]] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        stripped = line.rstrip()

        match = _SSL_CERTIFICATE.match(line)
        if match is not None:
            value = _unquote(match.group("value"))
            if value:
                latest[CONFIGURED_CERTIFICATE_PATH] = (line_number, stripped, value)
            continue

        match = _SERVER_NAME.match(line)
        if match is not None:
            names = _unquote(match.group("value")).split()
            if names:
                latest[CONFIGURED_SERVER_NAME] = (line_number, stripped, names)
            continue

        match = _SSL_PROTOCOLS.match(line)
        if match is not None:
            protocols = _unquote(match.group("value")).split()
            if protocols:
                latest[CONFIGURED_TLS_PROTOCOLS] = (line_number, stripped, protocols)
            continue

        match = _SSL_CIPHERS.match(line)
        if match is not None:
            suites = [item for item in _unquote(match.group("value")).split(":") if item]
            if suites:
                latest[CONFIGURED_CIPHER_SUITES] = (line_number, stripped, suites)
            continue

    return [
        (latest[predicate][0], latest[predicate][1], predicate, latest[predicate][2])
        for predicate in _DIRECTIVE_ORDER
        if predicate in latest
    ]


def _unquote(raw: str) -> str:
    return raw.strip().strip('"').strip("'")


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
