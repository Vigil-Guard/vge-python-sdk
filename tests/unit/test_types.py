"""Unit tests for type enums."""

from __future__ import annotations

import pytest

from vigil import Decision, Source, ThreatLevel


@pytest.mark.unit
class TestDecision:
    """Tests for Decision enum."""

    def test_allowed(self) -> None:
        assert Decision.ALLOWED.value == "ALLOWED"
        assert Decision.ALLOWED == "ALLOWED"

    def test_blocked(self) -> None:
        assert Decision.BLOCKED.value == "BLOCKED"
        assert Decision.BLOCKED == "BLOCKED"

    def test_sanitized(self) -> None:
        assert Decision.SANITIZED.value == "SANITIZED"
        assert Decision.SANITIZED == "SANITIZED"

    def test_from_string(self) -> None:
        assert Decision("ALLOWED") == Decision.ALLOWED
        assert Decision("BLOCKED") == Decision.BLOCKED
        assert Decision("SANITIZED") == Decision.SANITIZED

    def test_invalid_value_raises(self) -> None:
        with pytest.raises(ValueError):
            Decision("INVALID")


@pytest.mark.unit
class TestThreatLevel:
    """Tests for ThreatLevel enum."""

    def test_values(self) -> None:
        assert ThreatLevel.LOW.value == "LOW"
        assert ThreatLevel.MEDIUM.value == "MEDIUM"
        assert ThreatLevel.HIGH.value == "HIGH"
        assert ThreatLevel.CRITICAL.value == "CRITICAL"

    def test_from_score_low(self) -> None:
        assert ThreatLevel.from_score(0) == ThreatLevel.LOW
        assert ThreatLevel.from_score(15) == ThreatLevel.LOW
        assert ThreatLevel.from_score(29) == ThreatLevel.LOW

    def test_from_score_medium(self) -> None:
        assert ThreatLevel.from_score(30) == ThreatLevel.MEDIUM
        assert ThreatLevel.from_score(50) == ThreatLevel.MEDIUM
        assert ThreatLevel.from_score(64) == ThreatLevel.MEDIUM

    def test_from_score_high(self) -> None:
        assert ThreatLevel.from_score(65) == ThreatLevel.HIGH
        assert ThreatLevel.from_score(75) == ThreatLevel.HIGH
        assert ThreatLevel.from_score(84) == ThreatLevel.HIGH

    def test_from_score_critical(self) -> None:
        assert ThreatLevel.from_score(85) == ThreatLevel.CRITICAL
        assert ThreatLevel.from_score(90) == ThreatLevel.CRITICAL
        assert ThreatLevel.from_score(100) == ThreatLevel.CRITICAL


@pytest.mark.unit
class TestSource:
    """Tests for Source enum."""

    def test_values(self) -> None:
        assert Source.USER_INPUT.value == "user_input"
        assert Source.TOOL_OUTPUT.value == "tool_output"
        assert Source.MODEL_OUTPUT.value == "model_output"

    def test_from_string(self) -> None:
        assert Source("user_input") == Source.USER_INPUT
        assert Source("tool_output") == Source.TOOL_OUTPUT
        assert Source("model_output") == Source.MODEL_OUTPUT

    def test_invalid_value_raises(self) -> None:
        with pytest.raises(ValueError):
            Source("INVALID")
