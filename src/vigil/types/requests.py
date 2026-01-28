"""
Vigil Guard SDK Request Payload Models.

Internal dataclasses for building API request payloads.
These are not part of the public API.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .enums import Source


@dataclass
class GuardInputPayload:
    """Payload for POST /v1/guard/input."""

    prompt: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API request body."""
        result: Dict[str, Any] = {
            "prompt": self.prompt,
            "mode": "full",
        }
        if self.metadata:
            result["metadata"] = self.metadata
        return result


@dataclass
class GuardOutputPayload:
    """Payload for POST /v1/guard/output."""

    output: str
    original_prompt: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API request body."""
        result: Dict[str, Any] = {
            "output": self.output,
            "mode": "full",
        }
        if self.original_prompt:
            result["originalPrompt"] = self.original_prompt
        if self.metadata:
            result["metadata"] = self.metadata
        return result


@dataclass
class GuardAnalyzePayload:
    """Payload for POST /v1/guard/analyze."""

    text: str
    source: Source
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API request body."""
        result: Dict[str, Any] = {
            "text": self.text,
            "source": self.source.value,
            "mode": "full",
        }
        if self.metadata:
            result["metadata"] = self.metadata
        return result


@dataclass
class BatchItem:
    """Single item in a batch request."""

    text: str
    source: Source = Source.USER_INPUT
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API request item."""
        result: Dict[str, Any] = {
            "text": self.text,
            "source": self.source.value,
            "mode": "full",
        }
        if self.metadata:
            result["metadata"] = self.metadata
        return result


@dataclass
class BatchPayload:
    """Payload for POST /v1/guard/batch."""

    items: List[BatchItem]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API request body."""
        return {"items": [item.to_dict() for item in self.items]}
