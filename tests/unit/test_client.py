"""Unit tests for sync Vigil client."""

from __future__ import annotations

import json

import pytest
import respx
from conftest import build_detection_response, build_opaque_response
from httpx import Response
from pydantic import ValidationError

from vigil import (
    MAX_BATCH_ITEMS,
    MAX_METADATA_BYTES,
    AgentPayload,
    BatchItem,
    ConversationMessagePayload,
    Decision,
    Source,
    ToolPayload,
    Vigil,
    VigilAPIError,
    VigilClientVersionError,
    VigilConfigurationError,
    VigilLicenseExpiredError,
    VigilLicenseRequiredError,
    VigilValidationError,
)

DUMMY_BASE_URL = "https://api.vigilguard.test.local"
DUMMY_API_KEY = "vg_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


@pytest.fixture
def respx_mock() -> respx.MockRouter:
    """Provide respx mock router."""
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as mock:
        yield mock


@pytest.fixture
def client() -> Vigil:
    """Create test client."""
    return Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)


class TestVigilClientInit:
    """Tests for client initialization."""

    def test_missing_api_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing API key raises configuration error."""
        monkeypatch.delenv("VIGIL_GUARD_API_KEY", raising=False)
        monkeypatch.delenv("VIGIL_GUARD_BASE_URL", raising=False)

        with pytest.raises(VigilConfigurationError, match="api_key is required"):
            Vigil(base_url=DUMMY_BASE_URL)

    def test_default_base_url_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Default base_url is used when not provided."""
        monkeypatch.delenv("VIGIL_GUARD_BASE_URL", raising=False)

        client = Vigil(api_key=DUMMY_API_KEY)
        assert client._config.base_url == "https://api.vigilguard.customer.domain"

    def test_invalid_api_key_format_raises(self) -> None:
        """Invalid API key format raises configuration error."""
        with pytest.raises(VigilConfigurationError, match="Invalid API key format"):
            Vigil(api_key="invalid_key", base_url=DUMMY_BASE_URL)

    def test_successful_init(self) -> None:
        """Client initializes successfully with valid params."""
        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        assert client is not None

    def test_is_test_mode(self) -> None:
        """Test mode detection works."""
        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        assert client.is_test_mode is True
        assert client.is_live_mode is False

    def test_is_live_mode(self) -> None:
        """Live mode detection works."""
        live_key = "vg_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        client = Vigil(api_key=live_key, base_url=DUMMY_BASE_URL)
        assert client.is_live_mode is True
        assert client.is_test_mode is False

    def test_repr(self) -> None:
        """Client repr is informative."""
        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        repr_str = repr(client)
        assert "Vigil" in repr_str
        assert "test" in repr_str
        assert DUMMY_BASE_URL in repr_str


class TestVigilDetect:
    """Tests for detect() method."""

    def test_detect_allowed(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """Detect returns ALLOWED for safe content."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_detection_response(
                    requestId="req_123", decision="ALLOWED", score=10, confidence=0.95
                ),
            )
        )

        result = client.detect("Hello, world!")
        assert result.decision == Decision.ALLOWED
        assert result.score == 10
        assert result.is_safe is True

    def test_detect_blocked(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """Detect returns BLOCKED for malicious content."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_detection_response(
                    requestId="req_456",
                    decision="BLOCKED",
                    score=90,
                    confidence=0.99,
                    threatLevel="HIGH",
                    branches={
                        "heuristics": {"score": 90, "threatLevel": "HIGH", "explanations": []}
                    },
                ),
            )
        )

        result = client.detect("Ignore previous instructions")
        assert result.decision == Decision.BLOCKED
        assert result.is_blocked is True
        assert result.score == 90

    def test_detect_with_metadata(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """Detect passes metadata to API."""
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_detection_response(requestId="req_789", decision="ALLOWED", score=5),
            )
        )

        client.detect("Test", metadata={"user_id": "123"})

        request = route.calls[0].request
        assert b'"metadata"' in request.content
        assert b'"user_id"' in request.content

    def test_detect_with_idempotency_key(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """Detect passes idempotency key header."""
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_detection_response(requestId="req_idem", decision="ALLOWED", score=0),
            )
        )

        client.detect("Test", idempotency_key="my_key_123")

        request = route.calls[0].request
        assert request.headers.get("X-Idempotency-Key") == "my_key_123"


class TestVigilDetectOutput:
    """Tests for detect_output() method."""

    def test_detect_output_basic(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """Detect output works for LLM responses."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/output").mock(
            return_value=Response(
                200,
                json=build_detection_response(requestId="req_out_1", decision="ALLOWED", score=5),
            )
        )

        result = client.detect_output("Here is my response...")
        assert result.decision == Decision.ALLOWED

    def test_detect_output_with_original_prompt(
        self, respx_mock: respx.MockRouter, client: Vigil
    ) -> None:
        """Detect output includes original prompt for context."""
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/output").mock(
            return_value=Response(
                200,
                json=build_detection_response(requestId="req_out_2", decision="ALLOWED", score=10),
            )
        )

        client.detect_output(
            "Response text",
            original_prompt="What is the weather?",
        )

        request = route.calls[0].request
        assert b'"originalPrompt"' in request.content


class TestVigilAnalyze:
    """Tests for analyze() method."""

    def test_analyze_user_input(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """Analyze with USER_INPUT source."""
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/analyze").mock(
            return_value=Response(
                200,
                json=build_detection_response(
                    requestId="req_analyze_1",
                    decision="ALLOWED",
                    score=15,
                ),
            )
        )

        result = client.analyze("Test text", Source.USER_INPUT)

        assert result.decision == Decision.ALLOWED
        request = route.calls[0].request
        assert b'"source":"user_input"' in request.content

    def test_analyze_llm_output(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """Analyze with MODEL_OUTPUT source."""
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/analyze").mock(
            return_value=Response(
                200,
                json=build_detection_response(
                    requestId="req_analyze_2",
                    decision="ALLOWED",
                    score=20,
                ),
            )
        )

        result = client.analyze("LLM response", Source.MODEL_OUTPUT)

        assert result.decision == Decision.ALLOWED
        request = route.calls[0].request
        assert b'"source":"model_output"' in request.content

    def test_analyze_with_metadata_remains_backward_compatible(
        self, respx_mock: respx.MockRouter, client: Vigil
    ) -> None:
        """Analyze still supports legacy metadata-only callers."""
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/analyze").mock(
            return_value=Response(
                200,
                json=build_detection_response(
                    requestId="req_analyze_legacy",
                    decision="ALLOWED",
                    score=12,
                ),
            )
        )

        client.analyze("legacy text", Source.MODEL_OUTPUT, metadata={"trace_id": "legacy-1"})

        body = json.loads(route.calls[0].request.content)
        assert body["source"] == "model_output"
        assert body["metadata"]["trace_id"] == "legacy-1"
        assert "agent" not in body
        assert "tool" not in body
        assert "conversation" not in body

    def test_analyze_with_typed_payloads(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """Analyze serializes typed agent/tool/conversation payloads."""
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/analyze").mock(
            return_value=Response(
                200,
                json=build_detection_response(
                    requestId="req_analyze_typed",
                    decision="ALLOWED",
                    score=8,
                ),
            )
        )

        client.analyze(
            "ls -la",
            Source.TOOL_INPUT,
            agent=AgentPayload(framework="claude-code", session_id="sess_1"),
            tool=ToolPayload(
                name="Bash",
                vendor="anthropic",
                args={"command": "ls -la"},
            ),
            conversation=[
                ConversationMessagePayload(role="system", content="You are a CLI agent."),
                ConversationMessagePayload(
                    role="tool",
                    content="total 4",
                    tool_name="Bash",
                    tool_id="toolu_123",
                ),
            ],
        )

        body = json.loads(route.calls[0].request.content)
        assert body["source"] == "tool_input"
        assert body["agent"]["framework"] == "claude-code"
        assert body["agent"]["sessionId"] == "sess_1"
        assert body["tool"]["name"] == "Bash"
        assert body["tool"]["vendor"] == "anthropic"
        assert body["tool"]["args"]["command"] == "ls -la"
        assert body["conversation"][0]["role"] == "system"
        assert body["conversation"][1]["toolName"] == "Bash"
        assert body["conversation"][1]["toolId"] == "toolu_123"

    def test_analyze_raises_client_version_error_for_pre_prd29_server(
        self, respx_mock: respx.MockRouter, client: Vigil
    ) -> None:
        """Typed analyze requests raise a friendly compatibility error on old servers."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/analyze").mock(
            return_value=Response(
                400,
                json={
                    "error": "Validation failed",
                    "details": [
                        {"path": "source", "message": "Invalid enum value 'tool_input'"},
                        {"path": "agent.framework", "message": "Unexpected field"},
                    ],
                },
            )
        )

        with pytest.raises(
            VigilClientVersionError,
            match="PRD_29-compatible server",
        ):
            client.analyze(
                "ls -la",
                Source.TOOL_INPUT,
                agent=AgentPayload(framework="claude-code"),
            )


class TestVigilBatch:
    """Tests for batch() method."""

    def test_batch_all_success(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """Batch processes multiple items successfully."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/batch").mock(
            return_value=Response(
                200,
                json={
                    "items": [
                        {
                            "index": 0,
                            "ok": True,
                            "response": build_detection_response(requestId="req_b1_0", score=5),
                        },
                        {
                            "index": 1,
                            "ok": True,
                            "response": build_detection_response(
                                requestId="req_b1_1",
                                decision="BLOCKED",
                                score=85,
                                threatLevel="HIGH",
                            ),
                        },
                    ]
                },
            )
        )

        items = [
            BatchItem(text="Hello"),
            BatchItem(text="Evil text", source=Source.USER_INPUT),
        ]
        result = client.batch(items)

        assert result.total == 2
        assert result.succeeded == 2
        assert result.failed == 0
        assert result.all_succeeded is True
        assert len(result.items) == 2

    def test_batch_partial_failure(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """Batch handles partial failures."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/batch").mock(
            return_value=Response(
                200,
                json={
                    "items": [
                        {
                            "index": 0,
                            "ok": True,
                            "response": build_detection_response(requestId="req_b2_0", score=5),
                        },
                        {
                            "index": 1,
                            "ok": False,
                            "error": {"code": "INVALID", "message": "Too long"},
                        },
                    ]
                },
            )
        )

        items = [BatchItem(text="OK"), BatchItem(text="Server-side failure")]
        result = client.batch(items)

        assert result.has_failures is True
        assert result.succeeded == 1
        assert result.failed == 1

    def test_batch_iteration(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """Batch results are iterable."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/batch").mock(
            return_value=Response(
                200,
                json={
                    "items": [
                        {
                            "index": 0,
                            "ok": True,
                            "response": build_detection_response(requestId="r0", score=1),
                        },
                        {
                            "index": 1,
                            "ok": True,
                            "response": build_detection_response(requestId="r1", score=2),
                        },
                    ]
                },
            )
        )

        items = [BatchItem(text="A"), BatchItem(text="B")]
        result = client.batch(items)

        indices = [item.index for item in result]
        assert indices == [0, 1]

    def test_batch_serializes_typed_fields(
        self, respx_mock: respx.MockRouter, client: Vigil
    ) -> None:
        """Batch items preserve typed payload fields."""
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/batch").mock(
            return_value=Response(
                200,
                json={
                    "items": [
                        {
                            "index": 0,
                            "ok": True,
                            "response": build_detection_response(
                                requestId="req_batch_typed",
                                decision="ALLOWED",
                                score=3,
                            ),
                        }
                    ]
                },
            )
        )

        client.batch(
            [
                BatchItem(
                    text="tool output",
                    source=Source.TOOL_OUTPUT,
                    metadata={"trace_id": "batch-1"},
                    agent=AgentPayload(framework="openai-agents", trace_id="trace_1"),
                    tool=ToolPayload(name="WebFetch", vendor="openai"),
                    conversation=[
                        ConversationMessagePayload(role="assistant", content="Calling tool"),
                    ],
                )
            ]
        )

        body = json.loads(route.calls[0].request.content)
        assert body["items"][0]["source"] == "tool_output"
        assert body["items"][0]["metadata"]["trace_id"] == "batch-1"
        assert body["items"][0]["agent"]["framework"] == "openai-agents"
        assert body["items"][0]["agent"]["traceId"] == "trace_1"
        assert body["items"][0]["tool"]["name"] == "WebFetch"
        assert body["items"][0]["conversation"][0]["role"] == "assistant"

    def test_batch_rejects_more_than_static_contract_cap(self, client: Vigil) -> None:
        """SDK mirrors the v1.8 static /v1/guard/batch cap."""
        with pytest.raises(VigilValidationError) as exc_info:
            client.batch([BatchItem(text=f"Item {i}") for i in range(MAX_BATCH_ITEMS + 1)])

        assert exc_info.value.errors[0]["path"] == "items"
        assert str(MAX_BATCH_ITEMS) in exc_info.value.errors[0]["message"]

    def test_batch_rejects_empty_text(self, client: Vigil) -> None:
        """SDK mirrors the 1-100000 text length contract."""
        with pytest.raises(VigilValidationError) as exc_info:
            client.batch([BatchItem(text="")])

        assert exc_info.value.errors[0]["path"] == "items[].text"

    def test_batch_rejects_metadata_over_16k(self, client: Vigil) -> None:
        """SDK mirrors the v1.8 serialized metadata byte cap."""
        metadata = {"payload": "x" * MAX_METADATA_BYTES}

        with pytest.raises(VigilValidationError) as exc_info:
            client.batch([BatchItem(text="ok", metadata=metadata)])

        assert exc_info.value.errors[0]["path"] == "items[].metadata"
        assert str(MAX_METADATA_BYTES) in exc_info.value.errors[0]["message"]

    def test_batch_budget_error_exposes_max_safe_items(
        self, respx_mock: respx.MockRouter, client: Vigil
    ) -> None:
        """v1.8 batch budget errors expose maxSafeItems for split-and-retry clients."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/batch").mock(
            return_value=Response(
                400,
                json={
                    "error": "Batch too large for configured timeout budget",
                    "maxSafeItems": 8,
                    "requestId": "req_budget",
                },
            )
        )

        with pytest.raises(VigilValidationError) as exc_info:
            client.batch([BatchItem(text=f"Item {i}") for i in range(9)])

        assert exc_info.value.max_safe_items == 8
        assert exc_info.value.request_id == "req_budget"


class TestVigilWithOptions:
    """Tests for with_options() method."""

    def test_with_options_timeout(self, respx_mock: respx.MockRouter) -> None:
        """with_options creates new client with modified timeout."""
        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL, timeout=30.0)
        new_client = client.with_options(timeout=60.0)

        assert new_client is not client
        assert new_client._config.timeout == 60.0
        assert client._config.timeout == 30.0

    def test_with_options_max_retries(self) -> None:
        """with_options creates new client with modified retries."""
        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL, max_retries=3)
        new_client = client.with_options(max_retries=5)

        assert new_client._config.max_retries == 5
        assert client._config.max_retries == 3


class TestVigilContextManager:
    """Tests for context manager support."""

    def test_context_manager(self, respx_mock: respx.MockRouter) -> None:
        """Client can be used as context manager."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_detection_response(requestId="req_ctx", decision="ALLOWED", score=0),
            )
        )

        with Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL) as client:
            result = client.detect("Test")
            assert result.decision == Decision.ALLOWED

    def test_close(self) -> None:
        """Client close releases resources."""
        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        client.close()
        assert client._transport._client is None


class TestVigilGetLicenseStatus:
    """Tests for get_license_status() method."""

    def test_get_license_status_active(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """Get license status returns active license."""
        respx_mock.get(f"{DUMMY_BASE_URL}/v1/license/status").mock(
            return_value=Response(
                200,
                json={
                    "status": "ACTIVE",
                    "type": "ENTERPRISE",
                    "expiresAt": "2025-12-31T23:59:59Z",
                    "daysRemaining": 365,
                    "isBuiltIn": False,
                },
            )
        )

        result = client.get_license_status()
        assert result.status == "ACTIVE"
        assert result.type == "ENTERPRISE"
        assert result.is_active is True
        assert result.is_expired is False
        assert result.days_remaining == 365

    def test_get_license_status_trial(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """Get license status returns trial license."""
        respx_mock.get(f"{DUMMY_BASE_URL}/v1/license/status").mock(
            return_value=Response(
                200,
                json={
                    "status": "TRIAL",
                    "type": "TRIAL",
                    "expiresAt": "2024-02-15T23:59:59Z",
                    "daysRemaining": 14,
                    "isBuiltIn": True,
                },
            )
        )

        result = client.get_license_status()
        assert result.status == "TRIAL"
        assert result.is_active is True
        assert result.is_built_in is True

    def test_get_license_status_expired(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """Get license status returns expired license."""
        respx_mock.get(f"{DUMMY_BASE_URL}/v1/license/status").mock(
            return_value=Response(
                200,
                json={
                    "status": "EXPIRED",
                    "type": "PROFESSIONAL",
                    "expiresAt": "2024-01-01T00:00:00Z",
                    "daysRemaining": None,
                    "isBuiltIn": False,
                },
            )
        )

        result = client.get_license_status()
        assert result.status == "EXPIRED"
        assert result.is_expired is True
        assert result.is_active is False

    def test_get_license_status_expiring_soon(
        self, respx_mock: respx.MockRouter, client: Vigil
    ) -> None:
        """Get license status detects expiring soon."""
        respx_mock.get(f"{DUMMY_BASE_URL}/v1/license/status").mock(
            return_value=Response(
                200,
                json={
                    "status": "ACTIVE",
                    "type": "PROFESSIONAL",
                    "expiresAt": "2024-02-10T23:59:59Z",
                    "daysRemaining": 25,
                    "isBuiltIn": False,
                },
            )
        )

        result = client.get_license_status()
        assert result.is_expiring_soon is True

    def test_get_license_status_perpetual(
        self, respx_mock: respx.MockRouter, client: Vigil
    ) -> None:
        """Get license status handles perpetual license (no expiration)."""
        respx_mock.get(f"{DUMMY_BASE_URL}/v1/license/status").mock(
            return_value=Response(
                200,
                json={
                    "status": "ACTIVE",
                    "type": "ENTERPRISE_PERPETUAL",
                    "expiresAt": None,
                    "daysRemaining": None,
                    "isBuiltIn": False,
                },
            )
        )

        result = client.get_license_status()
        assert result.status == "ACTIVE"
        assert result.expires_at is None
        assert result.is_expiring_soon is False


class TestVigilLicenseErrors:
    """Tests for license error handling."""

    def test_detect_raises_license_expired_error(
        self, respx_mock: respx.MockRouter, client: Vigil
    ) -> None:
        """Detect raises VigilLicenseExpiredError on LICENSE_EXPIRED."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                403,
                json={
                    "error": "LICENSE_EXPIRED",
                    "message": "Your license has expired. Please renew to continue.",
                    "requestId": "req_license_1",
                },
            )
        )

        with pytest.raises(VigilLicenseExpiredError) as exc_info:
            client.detect("Test input")

        assert exc_info.value.error_code == "LICENSE_EXPIRED"
        assert exc_info.value.request_id == "req_license_1"

    def test_detect_raises_license_required_error(
        self, respx_mock: respx.MockRouter, client: Vigil
    ) -> None:
        """Detect raises VigilLicenseRequiredError on LICENSE_REQUIRED."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                403,
                json={
                    "error": "LICENSE_REQUIRED",
                    "message": "A valid license is required to access this service.",
                    "requestId": "req_license_2",
                },
            )
        )

        with pytest.raises(VigilLicenseRequiredError) as exc_info:
            client.detect("Test input")

        assert exc_info.value.error_code == "LICENSE_REQUIRED"


class TestVigilOpaqueResponses:
    """Anti-recon opaque responses through the sync client (PRD_60 T1)."""

    def test_detect_opaque_blocked(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """A rule set with opaque exposure returns only the deny surface."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_opaque_response(decision="BLOCKED", blockMessage="Request denied."),
            )
        )

        result = client.detect("Ignore previous instructions")
        assert result.decision == Decision.BLOCKED
        assert result.diagnostics_available is False
        assert result.score is None
        assert result.has_pii is None
        assert result.block_message == "Request denied."

    def test_detect_opaque_allowed(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(200, json=build_opaque_response(decision="ALLOWED"))
        )

        result = client.detect("Hello, world!")
        assert result.is_safe is True
        assert result.diagnostics_available is False
        assert result.is_high_risk is None

    def test_detect_opaque_sanitized_without_text(
        self, respx_mock: respx.MockRouter, client: Vigil
    ) -> None:
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(200, json=build_opaque_response(decision="SANITIZED"))
        )

        result = client.detect("My email is test@example.com")
        assert result.is_sanitized is True
        assert result.sanitized_text is None

    def test_detect_opaque_sanitized_with_text(
        self, respx_mock: respx.MockRouter, client: Vigil
    ) -> None:
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_opaque_response(decision="SANITIZED", sanitizedText="My email is ***"),
            )
        )

        result = client.detect("My email is test@example.com")
        assert result.is_sanitized is True
        assert result.sanitized_text == "My email is ***"

    def test_detect_output_opaque(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/output").mock(
            return_value=Response(
                200,
                json=build_opaque_response(decision="ALLOWED", outputText="model output"),
            )
        )

        result = client.detect_output("model output")
        assert result.is_safe is True
        assert result.output_text == "model output"
        assert result.diagnostics_available is False

    def test_batch_with_opaque_items(self, respx_mock: respx.MockRouter, client: Vigil) -> None:
        """Batch items reuse the same model: opaque and full items coexist."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/batch").mock(
            return_value=Response(
                200,
                json={
                    "items": [
                        {
                            "index": 0,
                            "ok": True,
                            "response": build_opaque_response(decision="BLOCKED"),
                        },
                        {
                            "index": 1,
                            "ok": True,
                            "response": build_detection_response(requestId="req_full"),
                        },
                    ]
                },
            )
        )

        result = client.batch([BatchItem(text="evil"), BatchItem(text="fine")])
        assert result.all_succeeded is True
        first = result[0].response
        assert first is not None
        assert first.diagnostics_available is False
        second = result[1].response
        assert second is not None
        assert second.diagnostics_available is True

    def test_detect_partial_profile_raises(
        self, respx_mock: respx.MockRouter, client: Vigil
    ) -> None:
        """A recon probe returning some diagnostics must not parse."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(200, json=build_opaque_response(score=10.0))
        )

        with pytest.raises(ValidationError, match="partial diagnostic profile"):
            client.detect("test")

    def test_strict_mode_accepts_pure_opaque(self, respx_mock: respx.MockRouter) -> None:
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(200, json=build_opaque_response(decision="ALLOWED"))
        )

        strict_client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL, strict_mode=True)
        result = strict_client.detect("test")
        assert result.diagnostics_available is False

    def test_strict_mode_rejects_opaque_with_extra_field(
        self, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200, json=build_opaque_response(decision="ALLOWED", futureField="x")
            )
        )

        strict_client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL, strict_mode=True)
        with pytest.raises(VigilAPIError, match="Unexpected fields"):
            strict_client.detect("test")

    def test_default_mode_ignores_opaque_extra_field(
        self, respx_mock: respx.MockRouter, client: Vigil
    ) -> None:
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200, json=build_opaque_response(decision="ALLOWED", futureField="x")
            )
        )

        result = client.detect("test")
        assert result.diagnostics_available is False
