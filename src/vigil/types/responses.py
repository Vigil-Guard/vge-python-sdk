"""
Vigil Guard SDK Response Models.

Pydantic models for API responses with convenience properties.
Uses extra="ignore" for forward-compatibility with new API fields.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .branches import DetectionBranches
from .enums import Decision, ThreatLevel

ArbiterSignal = Literal["ALLOW", "BLOCK"]
RuleAction = Literal["ALLOW", "BLOCK", "LOG", "SANITIZE"]


class LanguageInfo(BaseModel):
    """Detected language metadata."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    detected_language: str = Field(alias="detectedLanguage")
    confidence: float = Field(alias="confidence", ge=0.0, le=1.0)
    method: str = Field(alias="method")


class DetectionResult(BaseModel):
    """
    Result from a single detection request.

    This is the main response type for detect() and detect_output() methods.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    request_id: str = Field(alias="requestId")
    decision: Decision = Field(alias="decision")
    score: float = Field(alias="score", ge=0.0, le=100.0)
    threat_level: ThreatLevel = Field(alias="threatLevel")
    confidence: float = Field(alias="confidence", ge=0.0, le=1.0)
    categories: List[str] = Field(alias="categories")
    branches: DetectionBranches = Field(alias="branches")
    latency_ms: int = Field(alias="latencyMs", ge=0)
    timestamp: datetime = Field(alias="timestamp")

    sanitized_text: Optional[str] = Field(default=None, alias="sanitizedText")
    output_text: Optional[str] = Field(default=None, alias="outputText")
    decision_reason: Optional[str] = Field(default=None, alias="decisionReason")
    missing_branches: Optional[List[str]] = Field(default=None, alias="missingBranches")
    waited_ms: Optional[int] = Field(default=None, alias="waitedMs", ge=0)
    decision_flags: Optional[List[str]] = Field(default=None, alias="decisionFlags")
    request_received_at: Optional[datetime] = Field(default=None, alias="requestReceivedAt")
    decision_finalized_at: Optional[datetime] = Field(default=None, alias="decisionFinalizedAt")
    decision_latency_ms: Optional[int] = Field(default=None, alias="decisionLatencyMs", ge=0)
    language_info: Optional[LanguageInfo] = Field(default=None, alias="languageInfo")

    arbiter_signal: Optional[ArbiterSignal] = Field(default=None, alias="arbiterSignal")
    rule_action: Optional[RuleAction] = Field(default=None, alias="ruleAction")
    rule_set_id: Optional[int] = Field(default=None, alias="ruleSetId", ge=0)
    rule_set_name: Optional[str] = Field(default=None, alias="ruleSetName")
    redaction_applied: Optional[bool] = Field(default=None, alias="redactionApplied")
    redacted_text: Optional[str] = Field(default=None, alias="redactedText")
    redaction_match_count: Optional[int] = Field(default=None, alias="redactionMatchCount", ge=0)
    fail_open: Optional[bool] = Field(default=None, alias="failOpen")
    block_message: Optional[str] = Field(default=None, alias="blockMessage")

    @model_validator(mode="after")
    def validate_sanitized_text(self) -> DetectionResult:
        """Ensure sanitized_text is present when decision is SANITIZED."""
        if self.decision == Decision.SANITIZED and self.sanitized_text is None:
            raise ValueError("sanitized_text is required when decision is SANITIZED")
        return self

    @property
    def is_safe(self) -> bool:
        """Check if content is safe (ALLOWED)."""
        return self.decision == Decision.ALLOWED

    @property
    def is_blocked(self) -> bool:
        """Check if content was blocked."""
        return self.decision == Decision.BLOCKED

    @property
    def is_sanitized(self) -> bool:
        """Check if content was sanitized."""
        return self.decision == Decision.SANITIZED

    @property
    def is_high_risk(self) -> bool:
        """Check if threat level is HIGH or CRITICAL."""
        return self.threat_level in {ThreatLevel.HIGH, ThreatLevel.CRITICAL}

    @property
    def has_pii(self) -> bool:
        """Check if PII was detected."""
        return self.branches.has_pii

    @property
    def is_drifted(self) -> bool:
        """Check if policy drift was detected with non-ON_SCOPE level."""
        drift = self.branches.semantic.policy_drift if self.branches.semantic else None
        return drift is not None and drift.available and drift.level not in (None, "ON_SCOPE")

    @property
    def drift_level(self) -> str | None:
        """Get policy drift level if available."""
        drift = self.branches.semantic.policy_drift if self.branches.semantic else None
        return drift.level if drift and drift.available else None

    @property
    def drift_score(self) -> float | None:
        """Get policy drift score if available."""
        drift = self.branches.semantic.policy_drift if self.branches.semantic else None
        return drift.drift_score if drift and drift.available else None


class BatchItemError(BaseModel):
    """Error details for a failed batch item."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    code: str = Field(alias="code")
    message: str = Field(alias="message")


class BatchItemResult(BaseModel):
    """
    Result for a single item in a batch request.

    Either response or error will be present, not both.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    index: int = Field(alias="index", ge=0)
    ok: bool = Field(alias="ok")
    response: Optional[DetectionResult] = Field(default=None, alias="response")
    error: Optional[BatchItemError] = Field(default=None, alias="error")

    @model_validator(mode="after")
    def validate_response_or_error(self) -> BatchItemResult:
        """Ensure response is present on success and error is present on failure."""
        if self.ok and self.response is None:
            raise ValueError("response is required when ok is true")
        if not self.ok and self.error is None:
            raise ValueError("error is required when ok is false")
        return self

    @property
    def success(self) -> bool:
        """Alias for ok."""
        return self.ok

    @property
    def result(self) -> Optional[DetectionResult]:
        """Alias for response."""
        return self.response

    def __bool__(self) -> bool:
        """Allow `if item:` syntax."""
        return self.ok


class BatchResult(BaseModel):
    """
    Result from a batch detection request.

    Provides iteration over results and convenience methods
    for handling partial failures.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    items: List[BatchItemResult] = Field(alias="items")

    @property
    def total(self) -> int:
        """Total number of items in the batch."""
        return len(self.items)

    @property
    def succeeded(self) -> int:
        """Number of successful items."""
        return sum(1 for item in self.items if item.ok)

    @property
    def failed(self) -> int:
        """Number of failed items."""
        return self.total - self.succeeded

    @property
    def all_succeeded(self) -> bool:
        """Check if all items succeeded."""
        return self.failed == 0

    @property
    def has_failures(self) -> bool:
        """Check if any items failed."""
        return self.failed > 0

    def successful_items(self) -> List[BatchItemResult]:
        """Get list of successful items."""
        return [item for item in self.items if item.ok]

    def failed_items(self) -> List[BatchItemResult]:
        """Get list of failed items."""
        return [item for item in self.items if not item.ok]

    def raise_for_failures(self) -> None:
        """
        Raise exception if any items failed.

        Raises:
            VigilBatchPartialFailure: If any items failed
        """
        if self.has_failures:
            from .._errors import VigilBatchPartialFailure

            successful = [
                {
                    "index": item.index,
                    "response": item.response.model_dump() if item.response else None,
                }
                for item in self.successful_items()
            ]
            failed = [
                {
                    "index": item.index,
                    "error": item.error.model_dump() if item.error else None,
                }
                for item in self.failed_items()
            ]
            raise VigilBatchPartialFailure(
                f"Batch request partially failed: {self.succeeded} succeeded, {self.failed} failed",
                successful=successful,
                failed=failed,
            )

    def __iter__(self) -> Iterator[BatchItemResult]:  # type: ignore[override]
        """Iterate over items."""
        return iter(self.items)

    def __len__(self) -> int:
        """Get number of items."""
        return len(self.items)

    def __getitem__(self, index: int) -> BatchItemResult:
        """Get item by index."""
        return self.items[index]


class LicenseStatus(BaseModel):
    """License status from /v1/license/status endpoint."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    status: str = Field(alias="status")
    type: Optional[str] = Field(default=None, alias="type")
    expires_at: Optional[str] = Field(default=None, alias="expiresAt")
    days_remaining: Optional[int] = Field(default=None, alias="daysRemaining")
    is_built_in: bool = Field(default=False, alias="isBuiltIn")

    @property
    def is_active(self) -> bool:
        """Check if license is currently active."""
        return self.status in ("ACTIVE", "TRIAL")

    @property
    def is_expired(self) -> bool:
        """Check if license has expired."""
        return self.status == "EXPIRED"

    @property
    def is_expiring_soon(self) -> bool:
        """Check if license expires within 30 days."""
        return self.days_remaining is not None and self.days_remaining <= 30
