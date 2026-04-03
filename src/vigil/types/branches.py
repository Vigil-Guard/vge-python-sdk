"""
Vigil Guard SDK Detection Branch Models.

Pydantic models for the detection branch results from the API.
Uses extra="ignore" for forward-compatibility with new API fields.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class HeuristicsBranch(BaseModel):
    """
    Results from heuristics-based detection.

    Analyzes text against known prompt injection techniques.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    score: float = Field(alias="score")
    threat_level: Literal["LOW", "MEDIUM", "HIGH"] = Field(alias="threatLevel")
    explanations: List[str] = Field(alias="explanations")
    features: Optional[Dict[str, Any]] = Field(default=None, alias="features")
    timing_ms: Optional[int] = Field(default=None, alias="timingMs")


class PolicyDriftSignal(BaseModel):
    """Policy drift detection signal from scope analysis."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    enabled: bool = Field(alias="enabled")
    available: bool = Field(alias="available")
    drift_score: Optional[float] = Field(default=None, alias="driftScore")
    level: Optional[Literal["ON_SCOPE", "NEAR_SCOPE", "OFF_SCOPE", "MANIPULATION"]] = Field(
        default=None, alias="level"
    )
    action: Literal["ALLOW", "BLOCK"] = Field(alias="action")
    explanation: str = Field(alias="explanation")
    sensitivity: Literal["relaxed", "balanced", "strict"] = Field(alias="sensitivity")
    scope_fingerprint: Optional[str] = Field(default=None, alias="scopeFingerprint")
    degraded_reason: Optional[str] = Field(default=None, alias="degradedReason")
    latency_ms: int = Field(alias="latencyMs")


class SemanticBranch(BaseModel):
    """
    Results from semantic/embedding-based detection.

    Uses vector similarity against known malicious patterns.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    score: float = Field(alias="score")
    attack_similarity: float = Field(alias="attackSimilarity")
    safe_similarity: float = Field(alias="safeSimilarity")
    matched_category: Optional[str] = Field(default=None, alias="matchedCategory")
    timing_ms: Optional[int] = Field(default=None, alias="timingMs")
    policy_drift: Optional[PolicyDriftSignal] = Field(default=None, alias="policyDrift")


class PiiBranch(BaseModel):
    """
    Results from PII detection.

    Identifies personally identifiable information in text.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    detected: bool = Field(alias="detected")
    entity_count: int = Field(alias="entityCount")
    categories: List[str] = Field(alias="categories")
    timing_ms: Optional[int] = Field(default=None, alias="timingMs")


class LlmGuardBranch(BaseModel):
    """
    Results from injection signal classification.

    Uses a classifier model to analyze potential prompt injections.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True, protected_namespaces=())

    score: float = Field(alias="score")
    verdict: str = Field(alias="verdict")
    model_used: str = Field(alias="modelUsed")
    timing_ms: Optional[int] = Field(default=None, alias="timingMs")


class ContentModCategoryResult(BaseModel):
    """Per-category content moderation classification."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str = Field(alias="name")
    score: float = Field(alias="score")
    triggered: bool = Field(alias="triggered")


class ContentModBranch(BaseModel):
    """
    Results from content moderation detection.

    Includes per-category classifications and policy action metadata.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True, protected_namespaces=())

    score: float = Field(alias="score")
    confidence: float = Field(alias="confidence")
    categories: List[ContentModCategoryResult] = Field(alias="categories")
    triggered_categories: List[str] = Field(alias="triggeredCategories")
    detected_language: str = Field(alias="detectedLanguage")
    model_used: str = Field(alias="modelUsed")
    suggested_action: str = Field(alias="suggestedAction")
    action_applied: Optional[str] = Field(default=None, alias="actionApplied")
    processing_time_ms: int = Field(alias="processingTimeMs")
    error: Optional[str] = Field(default=None, alias="error")
    error_detail: Optional[str] = Field(default=None, alias="errorDetail")


class DetectionBranches(BaseModel):
    """
    Container for all detection branch results.

    All branches are optional as not all may be enabled.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    heuristics: Optional[HeuristicsBranch] = Field(default=None, alias="heuristics")
    semantic: Optional[SemanticBranch] = Field(default=None, alias="semantic")
    pii: Optional[PiiBranch] = Field(default=None, alias="pii")
    llm_guard: Optional[LlmGuardBranch] = Field(default=None, alias="llmGuard")
    content_mod: Optional[ContentModBranch] = Field(default=None, alias="contentMod")

    @property
    def has_pii(self) -> bool:
        """Check if any PII was detected."""
        return self.pii is not None and self.pii.detected
