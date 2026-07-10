"""Unit tests for Pydantic models."""

from __future__ import annotations

import pytest
from conftest import build_detection_response, build_opaque_response
from pydantic import ValidationError

from vigil.types import (
    BatchResult,
    Decision,
    DetectionBranches,
    DetectionResult,
    HeuristicsBranch,
    LlmGuardBranch,
    PiiBranch,
    SemanticBranch,
    ThreatLevel,
)


@pytest.mark.unit
class TestHeuristicsBranch:
    """Tests for HeuristicsBranch model."""

    def test_parse_minimal(self) -> None:
        data = {"score": 25, "threatLevel": "LOW", "explanations": []}
        branch = HeuristicsBranch.model_validate(data)
        assert branch.score == 25
        assert branch.threat_level == "LOW"
        assert branch.explanations == []

    def test_parse_with_features(self) -> None:
        data = {
            "score": 50,
            "threatLevel": "HIGH",
            "explanations": ["Matched jailbreak pattern"],
            "features": {"patternCount": 3},
            "timingMs": 12,
        }
        branch = HeuristicsBranch.model_validate(data)
        assert branch.score == 50
        assert branch.threat_level == "HIGH"
        assert branch.features["patternCount"] == 3
        assert branch.timing_ms == 12

    def test_forward_compatibility(self) -> None:
        data = {"score": 10, "threatLevel": "LOW", "explanations": [], "newField": "ignored"}
        branch = HeuristicsBranch.model_validate(data)
        assert branch.score == 10


@pytest.mark.unit
class TestSemanticBranch:
    """Tests for SemanticBranch model."""

    def test_parse_full(self) -> None:
        data = {
            "score": 35,
            "attackSimilarity": 0.75,
            "safeSimilarity": 0.2,
            "matchedCategory": "jailbreak_attempt_v1",
        }
        branch = SemanticBranch.model_validate(data)
        assert branch.score == 35
        assert branch.attack_similarity == 0.75
        assert branch.safe_similarity == 0.2
        assert branch.matched_category == "jailbreak_attempt_v1"


@pytest.mark.unit
class TestPiiBranch:
    """Tests for PiiBranch model."""

    def test_parse_no_pii(self) -> None:
        data = {"detected": False, "entityCount": 0, "categories": []}
        branch = PiiBranch.model_validate(data)
        assert branch.detected is False
        assert branch.categories == []

    def test_parse_with_categories(self) -> None:
        data = {
            "detected": True,
            "entityCount": 2,
            "categories": ["EMAIL", "PHONE_NUMBER"],
            "timingMs": 5,
        }
        branch = PiiBranch.model_validate(data)
        assert branch.detected is True
        assert branch.entity_count == 2
        assert branch.categories == ["EMAIL", "PHONE_NUMBER"]
        assert branch.timing_ms == 5


@pytest.mark.unit
class TestLlmGuardBranch:
    """Tests for LlmGuardBranch model."""

    def test_parse_full(self) -> None:
        data = {"score": 80, "verdict": "SAFE", "modelUsed": "llm-safety-v2"}
        branch = LlmGuardBranch.model_validate(data)
        assert branch.score == 80
        assert branch.verdict == "SAFE"
        assert branch.model_used == "llm-safety-v2"


@pytest.mark.unit
class TestDetectionBranches:
    """Tests for DetectionBranches container."""

    def test_parse_all_branches(self) -> None:
        data = {
            "heuristics": {"score": 20, "threatLevel": "LOW", "explanations": []},
            "semantic": {"score": 15, "attackSimilarity": 0.3, "safeSimilarity": 0.2},
            "pii": {"detected": False, "entityCount": 0, "categories": []},
            "llmGuard": {
                "score": 10,
                "verdict": "SAFE",
                "modelUsed": "llm-safety-v2",
            },
        }
        branches = DetectionBranches.model_validate(data)
        assert branches.heuristics is not None
        assert branches.semantic is not None
        assert branches.pii is not None
        assert branches.llm_guard is not None

    def test_has_pii_false(self) -> None:
        data = {"pii": {"detected": False, "entityCount": 0, "categories": []}}
        branches = DetectionBranches.model_validate(data)
        assert branches.has_pii is False

    def test_has_pii_true(self) -> None:
        data = {"pii": {"detected": True, "entityCount": 1, "categories": ["EMAIL"]}}
        branches = DetectionBranches.model_validate(data)
        assert branches.has_pii is True


@pytest.mark.unit
class TestDetectionResult:
    """Tests for DetectionResult model."""

    def test_parse_minimal(self) -> None:
        data = build_detection_response()
        result = DetectionResult.model_validate(data)
        assert result.request_id == "req_123"
        assert result.decision == Decision.ALLOWED
        assert result.score == 10.0
        assert result.threat_level == ThreatLevel.LOW

    def test_parse_full(self) -> None:
        data = build_detection_response(
            requestId="req_456",
            decision="BLOCKED",
            score=90,
            confidence=0.98,
            threatLevel="CRITICAL",
            categories=["PROMPT_INJECTION"],
            branches={"heuristics": {"score": 85, "threatLevel": "HIGH", "explanations": ["rule"]}},
            latencyMs=150,
            decisionReason="Matched policy",
        )
        result = DetectionResult.model_validate(data)
        assert result.confidence == 0.98
        assert result.latency_ms == 150
        assert result.decision_reason == "Matched policy"
        assert result.branches.heuristics is not None

    def test_parse_sanitized(self) -> None:
        data = build_detection_response(
            requestId="req_789",
            decision="SANITIZED",
            score=45,
            threatLevel="MEDIUM",
            sanitizedText="cleaned text",
        )
        result = DetectionResult.model_validate(data)
        assert result.decision == Decision.SANITIZED
        assert result.sanitized_text == "cleaned text"

    def test_sanitized_without_text_raises(self) -> None:
        data = build_detection_response(requestId="req_bad", decision="SANITIZED", score=45)
        with pytest.raises(ValidationError) as exc_info:
            DetectionResult.model_validate(data)
        assert "sanitized_text" in str(exc_info.value)

    def test_invalid_score_raises(self) -> None:
        data = build_detection_response(requestId="req_bad", score=150)
        with pytest.raises(ValidationError):
            DetectionResult.model_validate(data)

    def test_invalid_confidence_raises(self) -> None:
        data = build_detection_response(requestId="req_bad", confidence=1.5)
        with pytest.raises(ValidationError):
            DetectionResult.model_validate(data)

    def test_is_safe(self) -> None:
        data = build_detection_response(decision="ALLOWED")
        result = DetectionResult.model_validate(data)
        assert result.is_safe is True
        assert result.is_blocked is False
        assert result.is_sanitized is False

    def test_is_blocked(self) -> None:
        data = build_detection_response(decision="BLOCKED")
        result = DetectionResult.model_validate(data)
        assert result.is_safe is False
        assert result.is_blocked is True

    def test_is_high_risk(self) -> None:
        data = build_detection_response(threatLevel="HIGH")
        result = DetectionResult.model_validate(data)
        assert result.is_high_risk is True

    def test_threat_level(self) -> None:
        data = build_detection_response(threatLevel="MEDIUM")
        result = DetectionResult.model_validate(data)
        assert result.threat_level == ThreatLevel.MEDIUM

    def test_forward_compatibility(self) -> None:
        data = build_detection_response(newField="ignored", futureMetrics={"x": 1})
        result = DetectionResult.model_validate(data)
        assert result.score == 10.0


@pytest.mark.unit
class TestBatchResult:
    """Tests for BatchResult model."""

    def test_parse_all_success(self) -> None:
        data = {
            "items": [
                {
                    "index": 0,
                    "ok": True,
                    "response": build_detection_response(requestId="r1"),
                },
                {
                    "index": 1,
                    "ok": True,
                    "response": build_detection_response(requestId="r2"),
                },
            ]
        }
        batch = BatchResult.model_validate(data)
        assert batch.total == 2
        assert batch.all_succeeded is True
        assert batch.has_failures is False
        assert len(batch) == 2

    def test_parse_partial_failure(self) -> None:
        data = {
            "items": [
                {
                    "index": 0,
                    "ok": True,
                    "response": build_detection_response(requestId="r1"),
                },
                {
                    "index": 1,
                    "ok": False,
                    "error": {"code": "VALIDATION_ERROR", "message": "Text too long"},
                },
            ]
        }
        batch = BatchResult.model_validate(data)
        assert batch.all_succeeded is False
        assert batch.has_failures is True
        assert len(batch.successful_items()) == 1
        assert len(batch.failed_items()) == 1

    def test_iteration(self) -> None:
        data = {
            "items": [
                {
                    "index": 0,
                    "ok": True,
                    "response": build_detection_response(requestId="r1"),
                },
                {
                    "index": 1,
                    "ok": True,
                    "response": build_detection_response(requestId="r2"),
                },
            ]
        }
        batch = BatchResult.model_validate(data)
        indices = [item.index for item in batch]
        assert indices == [0, 1]

    def test_getitem(self) -> None:
        data = {
            "items": [
                {
                    "index": 0,
                    "ok": True,
                    "response": build_detection_response(requestId="r1"),
                }
            ]
        }
        batch = BatchResult.model_validate(data)
        assert batch[0].index == 0

    def test_raise_for_failures_no_failures(self) -> None:
        data = {
            "items": [
                {
                    "index": 0,
                    "ok": True,
                    "response": build_detection_response(requestId="r1"),
                }
            ]
        }
        batch = BatchResult.model_validate(data)
        batch.raise_for_failures()

    def test_raise_for_failures_with_failures(self) -> None:
        from vigil import VigilBatchPartialFailure

        data = {
            "items": [
                {
                    "index": 0,
                    "ok": True,
                    "response": build_detection_response(requestId="r1"),
                },
                {
                    "index": 1,
                    "ok": False,
                    "error": {"code": "ERROR", "message": "Failed"},
                },
            ]
        }
        batch = BatchResult.model_validate(data)
        with pytest.raises(VigilBatchPartialFailure) as exc_info:
            batch.raise_for_failures()
        assert len(exc_info.value.successful) == 1
        assert len(exc_info.value.failed) == 1


# Server aliases of the six diagnostic fields with valid non-null values.
DIAGNOSTIC_ALIAS_VALUES: dict[str, object] = {
    "score": 10.0,
    "threatLevel": "LOW",
    "confidence": 0.9,
    "categories": [],
    "branches": {},
    "latencyMs": 5,
}


@pytest.mark.unit
class TestDetectionResultOpaqueProfile:
    """Opaque/full diagnostic-profile invariant (PRD_60 T1, ADR-0035)."""

    def test_opaque_allowed_parses(self) -> None:
        result = DetectionResult.model_validate(build_opaque_response(decision="ALLOWED"))
        assert result.decision == Decision.ALLOWED
        assert result.is_safe is True
        assert result.diagnostics_available is False
        assert result.score is None
        assert result.threat_level is None
        assert result.confidence is None
        assert result.categories is None
        assert result.branches is None
        assert result.latency_ms is None

    def test_opaque_blocked_parses_with_block_message(self) -> None:
        result = DetectionResult.model_validate(
            build_opaque_response(decision="BLOCKED", blockMessage="Request denied.")
        )
        assert result.is_blocked is True
        assert result.block_message == "Request denied."
        assert result.diagnostics_available is False

    def test_opaque_sanitized_without_text_parses(self) -> None:
        result = DetectionResult.model_validate(build_opaque_response(decision="SANITIZED"))
        assert result.is_sanitized is True
        assert result.sanitized_text is None
        assert result.diagnostics_available is False

    def test_opaque_sanitized_with_text_parses(self) -> None:
        result = DetectionResult.model_validate(
            build_opaque_response(decision="SANITIZED", sanitizedText="cleaned")
        )
        assert result.is_sanitized is True
        assert result.sanitized_text == "cleaned"

    def test_full_sanitized_without_text_still_rejected(self) -> None:
        data = build_detection_response(decision="SANITIZED")
        with pytest.raises(ValidationError, match="sanitized_text"):
            DetectionResult.model_validate(data)

    def test_opaque_diagnostic_properties_return_none(self) -> None:
        result = DetectionResult.model_validate(build_opaque_response())
        assert result.has_pii is None
        assert result.is_high_risk is None
        assert result.is_drifted is None
        assert result.drift_level is None
        assert result.drift_score is None

    def test_full_profile_zero_and_empty_values_are_present(self) -> None:
        data = build_detection_response(
            score=0.0, threatLevel="LOW", confidence=0.0, categories=[], branches={}, latencyMs=0
        )
        result = DetectionResult.model_validate(data)
        assert result.diagnostics_available is True
        assert result.score == 0.0
        assert result.confidence == 0.0
        assert result.categories == []
        assert result.latency_ms == 0
        assert result.is_high_risk is False

    @pytest.mark.parametrize("alias", sorted(DIAGNOSTIC_ALIAS_VALUES))
    def test_single_diagnostic_field_supplied_rejected(self, alias: str) -> None:
        data = build_opaque_response(**{alias: DIAGNOSTIC_ALIAS_VALUES[alias]})
        with pytest.raises(ValidationError, match="partial diagnostic profile"):
            DetectionResult.model_validate(data)

    @pytest.mark.parametrize("alias", sorted(DIAGNOSTIC_ALIAS_VALUES))
    def test_single_diagnostic_field_missing_rejected(self, alias: str) -> None:
        data = build_detection_response()
        del data[alias]
        with pytest.raises(ValidationError, match="partial diagnostic profile"):
            DetectionResult.model_validate(data)

    @pytest.mark.parametrize("alias", sorted(DIAGNOSTIC_ALIAS_VALUES))
    def test_single_explicit_null_diagnostic_rejected(self, alias: str) -> None:
        data = build_detection_response(**{alias: None})
        with pytest.raises(ValidationError, match="supplied as null"):
            DetectionResult.model_validate(data)

    def test_all_six_explicit_null_rejected(self) -> None:
        data = build_detection_response(
            score=None,
            threatLevel=None,
            confidence=None,
            categories=None,
            branches=None,
            latencyMs=None,
        )
        with pytest.raises(ValidationError, match="supplied as null"):
            DetectionResult.model_validate(data)

    def test_field_name_input_full_profile(self) -> None:
        data = {
            "requestId": "req_names",
            "decision": "ALLOWED",
            "timestamp": "2024-01-15T10:30:00Z",
            "score": 10.0,
            "threat_level": "LOW",
            "confidence": 0.9,
            "categories": [],
            "branches": {},
            "latency_ms": 5,
        }
        result = DetectionResult.model_validate(data)
        assert result.diagnostics_available is True
        assert result.threat_level == ThreatLevel.LOW
        assert result.latency_ms == 5

    def test_field_name_single_field_rejected(self) -> None:
        data = build_opaque_response(threat_level="LOW")
        with pytest.raises(ValidationError, match="partial diagnostic profile"):
            DetectionResult.model_validate(data)

    def test_mixed_alias_and_field_name_full_profile(self) -> None:
        data = build_detection_response()
        del data["threatLevel"]
        del data["latencyMs"]
        data["threat_level"] = "LOW"
        data["latency_ms"] = 5
        result = DetectionResult.model_validate(data)
        assert result.diagnostics_available is True

    def test_opaque_extra_field_ignored_at_model_level(self) -> None:
        result = DetectionResult.model_validate(build_opaque_response(futureField="ignored"))
        assert result.diagnostics_available is False

    def test_batch_item_accepts_opaque_response(self) -> None:
        data = {
            "items": [
                {"index": 0, "ok": True, "response": build_opaque_response(decision="ALLOWED")},
                {"index": 1, "ok": True, "response": build_detection_response(requestId="r_full")},
            ]
        }
        batch = BatchResult.model_validate(data)
        assert batch.all_succeeded is True
        first = batch[0].response
        assert first is not None
        assert first.diagnostics_available is False
        second = batch[1].response
        assert second is not None
        assert second.diagnostics_available is True
