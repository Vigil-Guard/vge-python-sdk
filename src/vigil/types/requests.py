"""
Vigil Guard SDK Request Payload Models.

Small typed payload helpers are part of the public API. Endpoint payload wrappers
remain internal implementation details used by the sync and async clients.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .enums import Source


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
        return {"items": [item.to_dict() for item in self.items]}
