"""Tests for PolicyDriftSignal model and convenience properties."""

from vigil.types.branches import PolicyDriftSignal, SemanticBranch
from vigil.types.responses import DetectionResult


def test_policy_drift_signal_from_api_response():
    signal = PolicyDriftSignal.model_validate(
        {
            "enabled": True,
            "available": True,
            "driftScore": 0.74,
            "level": "OFF_SCOPE",
            "action": "ALLOW",
            "explanation": "Input appears outside the configured scope",
            "sensitivity": "balanced",
            "scopeFingerprint": "sha256:abc123",
            "latencyMs": 3,
        }
    )
    assert signal.available is True
    assert signal.drift_score == 0.74
    assert signal.level == "OFF_SCOPE"
    assert signal.action == "ALLOW"
    assert signal.scope_fingerprint == "sha256:abc123"


def test_semantic_branch_with_policy_drift():
    branch = SemanticBranch.model_validate(
        {
            "score": 8,
            "attackSimilarity": 0.42,
            "safeSimilarity": 0.68,
            "policyDrift": {
                "enabled": True,
                "available": True,
                "driftScore": 0.9,
                "level": "MANIPULATION",
                "action": "BLOCK",
                "explanation": "Manipulation detected",
                "sensitivity": "strict",
                "latencyMs": 2,
            },
        }
    )
    assert branch.policy_drift is not None
    assert branch.policy_drift.level == "MANIPULATION"
    assert branch.policy_drift.action == "BLOCK"


def test_semantic_branch_without_policy_drift():
    branch = SemanticBranch.model_validate(
        {
            "score": 5,
            "attackSimilarity": 0.3,
            "safeSimilarity": 0.7,
        }
    )
    assert branch.policy_drift is None


def test_detection_result_drift_convenience_props():
    result = DetectionResult.model_validate(
        {
            "requestId": "req-1",
            "decision": "ALLOWED",
            "score": 8,
            "threatLevel": "LOW",
            "confidence": 0.95,
            "categories": [],
            "branches": {
                "semantic": {
                    "score": 8,
                    "attackSimilarity": 0.42,
                    "safeSimilarity": 0.68,
                    "policyDrift": {
                        "enabled": True,
                        "available": True,
                        "driftScore": 0.74,
                        "level": "OFF_SCOPE",
                        "action": "ALLOW",
                        "explanation": "Outside scope",
                        "sensitivity": "balanced",
                        "latencyMs": 3,
                    },
                },
            },
            "latencyMs": 150,
            "timestamp": "2026-04-03T12:00:00Z",
        }
    )
    assert result.is_drifted is True
    assert result.drift_level == "OFF_SCOPE"
    assert result.drift_score == 0.74


def test_detection_result_no_drift():
    result = DetectionResult.model_validate(
        {
            "requestId": "req-2",
            "decision": "ALLOWED",
            "score": 5,
            "threatLevel": "LOW",
            "confidence": 0.9,
            "categories": [],
            "branches": {
                "semantic": {
                    "score": 5,
                    "attackSimilarity": 0.3,
                    "safeSimilarity": 0.7,
                },
            },
            "latencyMs": 100,
            "timestamp": "2026-04-03T12:00:00Z",
        }
    )
    assert result.is_drifted is False
    assert result.drift_level is None
    assert result.drift_score is None


def test_on_scope_is_not_drifted():
    result = DetectionResult.model_validate(
        {
            "requestId": "req-3",
            "decision": "ALLOWED",
            "score": 3,
            "threatLevel": "LOW",
            "confidence": 0.95,
            "categories": [],
            "branches": {
                "semantic": {
                    "score": 3,
                    "attackSimilarity": 0.1,
                    "safeSimilarity": 0.9,
                    "policyDrift": {
                        "enabled": True,
                        "available": True,
                        "driftScore": 0.1,
                        "level": "ON_SCOPE",
                        "action": "ALLOW",
                        "explanation": "Within scope",
                        "sensitivity": "balanced",
                        "latencyMs": 2,
                    },
                },
            },
            "latencyMs": 100,
            "timestamp": "2026-04-03T12:00:00Z",
        }
    )
    assert result.is_drifted is False
    assert result.drift_level == "ON_SCOPE"
