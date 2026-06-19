"""
Vigil Guard SDK Request Payload Models.

Small typed payload helpers are part of the public API. Endpoint payload wrappers
remain internal implementation details used by the sync and async clients.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .._errors import VigilValidationError
from .enums import Source

MIN_TEXT_LENGTH = 1
MAX_TEXT_LENGTH = 100_000
MAX_BATCH_ITEMS = 24
MAX_METADATA_BYTES = 16 * 1024


@dataclass
class AgentPayload:
    """Typed agent metadata for PRD_29-compatible servers."""

    framework: Optional[str] = None
    version: Optional[str] = None
    session_id: Optional[str] = None
    trace_id: Optional[str] = None
    hook_event: Optional[str] = None
    mcp_server: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API request body."""
        result: Dict[str, Any] = {}
        if self.framework is not None:
            result["framework"] = self.framework
        if self.version is not None:
            result["version"] = self.version
        if self.session_id is not None:
            result["sessionId"] = self.session_id
        if self.trace_id is not None:
            result["traceId"] = self.trace_id
        if self.hook_event is not None:
            result["hookEvent"] = self.hook_event
        if self.mcp_server is not None:
            result["mcpServer"] = self.mcp_server
        return result


@dataclass
class ToolResultPayload:
    """Typed tool result payload."""

    content: Any
    is_error: Optional[bool] = None
    duration_ms: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API request body."""
        result: Dict[str, Any] = {"content": self.content}
        if self.is_error is not None:
            result["isError"] = self.is_error
        if self.duration_ms is not None:
            result["durationMs"] = self.duration_ms
        return result


@dataclass
class ToolPayload:
    """Typed tool invocation payload."""

    name: str
    id: Optional[str] = None
    vendor: Optional[str] = None
    args: Optional[Any] = None
    result: Optional[ToolResultPayload] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API request body."""
        result: Dict[str, Any] = {"name": self.name}
        if self.id is not None:
            result["id"] = self.id
        if self.vendor is not None:
            result["vendor"] = self.vendor
        if self.args is not None:
            result["args"] = self.args
        if self.result is not None:
            result["result"] = self.result.to_dict()
        return result


@dataclass
class ConversationMessagePayload:
    """Typed conversation message payload."""

    role: str
    content: str
    tool_name: Optional[str] = None
    tool_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API request body."""
        result: Dict[str, Any] = {
            "role": self.role,
            "content": self.content,
        }
        if self.tool_name is not None:
            result["toolName"] = self.tool_name
        if self.tool_id is not None:
            result["toolId"] = self.tool_id
        return result


@dataclass
class GuardInputPayload:
    """Payload for POST /v1/guard/input."""

    prompt: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    agent: Optional[AgentPayload] = None
    tool: Optional[ToolPayload] = None
    conversation: List[ConversationMessagePayload] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API request body."""
        _validate_text("prompt", self.prompt)
        _validate_metadata(self.metadata)
        result: Dict[str, Any] = {
            "prompt": self.prompt,
            "mode": "full",
        }
        if self.metadata:
            result["metadata"] = self.metadata
        if self.agent is not None:
            result["agent"] = self.agent.to_dict()
        if self.tool is not None:
            result["tool"] = self.tool.to_dict()
        if self.conversation:
            result["conversation"] = [message.to_dict() for message in self.conversation]
        return result


@dataclass
class GuardOutputPayload:
    """Payload for POST /v1/guard/output."""

    output: str
    original_prompt: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    agent: Optional[AgentPayload] = None
    tool: Optional[ToolPayload] = None
    conversation: List[ConversationMessagePayload] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API request body."""
        _validate_text("output", self.output)
        _validate_text("originalPrompt", self.original_prompt, required=False)
        _validate_metadata(self.metadata)
        result: Dict[str, Any] = {
            "output": self.output,
            "mode": "full",
        }
        if self.original_prompt:
            result["originalPrompt"] = self.original_prompt
        if self.metadata:
            result["metadata"] = self.metadata
        if self.agent is not None:
            result["agent"] = self.agent.to_dict()
        if self.tool is not None:
            result["tool"] = self.tool.to_dict()
        if self.conversation:
            result["conversation"] = [message.to_dict() for message in self.conversation]
        return result


@dataclass
class GuardAnalyzePayload:
    """Payload for POST /v1/guard/analyze."""

    text: str
    source: Source
    metadata: Dict[str, Any] = field(default_factory=dict)
    agent: Optional[AgentPayload] = None
    tool: Optional[ToolPayload] = None
    conversation: List[ConversationMessagePayload] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API request body."""
        _validate_text("text", self.text)
        _validate_metadata(self.metadata)
        result: Dict[str, Any] = {
            "text": self.text,
            "source": self.source.value,
            "mode": "full",
        }
        if self.metadata:
            result["metadata"] = self.metadata
        if self.agent is not None:
            result["agent"] = self.agent.to_dict()
        if self.tool is not None:
            result["tool"] = self.tool.to_dict()
        if self.conversation:
            result["conversation"] = [message.to_dict() for message in self.conversation]
        return result


@dataclass
class BatchItem:
    """Single item in a batch request."""

    text: str
    source: Source = Source.USER_INPUT
    metadata: Dict[str, Any] = field(default_factory=dict)
    agent: Optional[AgentPayload] = None
    tool: Optional[ToolPayload] = None
    conversation: List[ConversationMessagePayload] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API request item."""
        _validate_text("items[].text", self.text)
        _validate_metadata(self.metadata, path="items[].metadata")
        result: Dict[str, Any] = {
            "text": self.text,
            "source": self.source.value,
            "mode": "full",
        }
        if self.metadata:
            result["metadata"] = self.metadata
        if self.agent is not None:
            result["agent"] = self.agent.to_dict()
        if self.tool is not None:
            result["tool"] = self.tool.to_dict()
        if self.conversation:
            result["conversation"] = [message.to_dict() for message in self.conversation]
        return result


@dataclass
class BatchPayload:
    """Payload for POST /v1/guard/batch."""

    items: List[BatchItem]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API request body."""
        count = len(self.items)
        if count < 1 or count > MAX_BATCH_ITEMS:
            _raise_validation_error(
                "items",
                f"batch items must contain 1-{MAX_BATCH_ITEMS} entries",
            )
        return {"items": [item.to_dict() for item in self.items]}


def _validate_text(path: str, value: Optional[str], *, required: bool = True) -> None:
    if value is None:
        if required:
            _raise_validation_error(path, f"{path} is required")
        return
    length = len(value)
    if length < MIN_TEXT_LENGTH or length > MAX_TEXT_LENGTH:
        _raise_validation_error(
            path,
            f"{path} must be {MIN_TEXT_LENGTH}-{MAX_TEXT_LENGTH} characters",
        )


def _validate_metadata(metadata: Dict[str, Any], *, path: str = "metadata") -> None:
    if not metadata:
        return
    size = _stable_serialized_bytes(metadata)
    if size > MAX_METADATA_BYTES:
        _raise_validation_error(
            path,
            f"{path} exceeds {MAX_METADATA_BYTES} bytes when serialized",
        )


def _stable_serialized_bytes(value: Any) -> int:
    try:
        serialized = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise VigilValidationError(
            "metadata must be JSON serializable",
            errors=[{"path": "metadata", "message": "metadata must be JSON serializable"}],
        ) from exc
    return len(serialized.encode("utf-8"))


def _raise_validation_error(path: str, message: str) -> None:
    raise VigilValidationError(
        message,
        errors=[{"path": path, "message": message}],
    )
