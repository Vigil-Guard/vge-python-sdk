"""
Vigil Guard SDK Enumerations.

Defines the core enums used throughout the SDK for type safety.
"""

from __future__ import annotations

from enum import Enum


class Decision(str, Enum):
    """
    Detection decision returned by the API.

    Values:
        ALLOWED: Content is safe, no action needed
        BLOCKED: Content is malicious, reject entirely
        SANITIZED: Content was modified to remove threats
    """

    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    SANITIZED = "SANITIZED"


class ThreatLevel(str, Enum):
    """
    Threat severity classification.

    Values:
        LOW: Score 0-29, minimal risk
        MEDIUM: Score 30-64, moderate risk
        HIGH: Score 65-84, significant risk
        CRITICAL: Score 85-100, severe risk
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_score(cls, score: int) -> ThreatLevel:
        """Determine threat level from numeric score (0-100)."""
        if score < 30:
            return cls.LOW
        if score < 65:
            return cls.MEDIUM
        if score < 85:
            return cls.HIGH
        return cls.CRITICAL


class Source(str, Enum):
    """
    Content source classification for analyze endpoint.

    Values:
        USER_INPUT: Direct user input to the LLM
        TOOL_OUTPUT: Output from an LLM tool/function call
        MODEL_OUTPUT: Generated content from the LLM
    """

    USER_INPUT = "user_input"
    TOOL_OUTPUT = "tool_output"
    MODEL_OUTPUT = "model_output"
