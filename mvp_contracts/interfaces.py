"""Public module boundaries; these protocols contain no business implementation."""

from datetime import datetime
from pathlib import Path
from typing import Protocol

from .models import (
    Artifact,
    BundleManifest,
    Decision,
    EvidenceSnapshot,
    ParseRequest,
    ParseResult,
    ReportArtifact,
    ReviewEvent,
    RulePack,
    VerifyResult,
)


class Parser(Protocol):
    def parse(self, request: ParseRequest) -> ParseResult: ...


class IdAllocator(Protocol):
    def allocate(self, *, prefix: str, project_id: str) -> str: ...


class EvidenceBuilder(Protocol):
    def build_snapshot(
        self,
        *,
        project_id: str,
        evaluation_time: datetime,
        rule_version: str,
        artifacts: list[Artifact],
        parse_results: list[ParseResult],
        review_events: list[ReviewEvent],
    ) -> EvidenceSnapshot: ...


class DecisionEngine(Protocol):
    def evaluate(self, snapshot: EvidenceSnapshot, rule_pack: RulePack) -> list[Decision]: ...


class BundleExporter(Protocol):
    def export_bundle(
        self,
        snapshot: EvidenceSnapshot,
        decisions: list[Decision],
        report: ReportArtifact,
    ) -> BundleManifest: ...


class BundleVerifier(Protocol):
    def verify(self, bundle_path: Path) -> VerifyResult: ...
