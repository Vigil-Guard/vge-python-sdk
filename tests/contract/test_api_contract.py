"""
Contract tests for Vigil Guard API.

These tests verify that SDK models correctly parse all documented API response formats.
They ensure the SDK remains compatible with the API contract defined in openapi.yaml.
"""

from __future__ import annotations

import pytest
import respx
from conftest import build_detection_response
from httpx import Response

from vigil import (
    AsyncVigil,
    BatchItem,
    Decision,
    Source,
    ThreatLevel,
    Vigil,
    VigilAuthenticationError,
    VigilRateLimitError,
    VigilServiceError,
    VigilValidationError,
)

DUMMY_BASE_URL = "https://api.vigilguard.test.local"
DUMMY_API_KEY = "vg_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


@pytest.fixture
def respx_mock() -> respx.MockRouter:
    """Provide respx mock router."""
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as mock:
        yield mock


class TestDetectionResponseContract:
    """Contract tests for /v1/guard/input response schema."""

    def test_minimal_response(self, respx_mock: respx.MockRouter) -> None:
        """Minimal valid response with only required fields."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_detection_response(requestId="req_minimal", decision="ALLOWED", score=0),
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        result = client.detect("test")

        assert result.request_id == "req_minimal"
        assert result.decision == Decision.ALLOWED
        assert result.score == 0

    def test_full_response_all_branches(self, respx_mock: respx.MockRouter) -> None:
        """Full response with all optional branches populated."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_detection_response(
                    requestId="req_full",
                    decision="BLOCKED",
                    score=95,
                    threatLevel="CRITICAL",
                    confidence=0.99,
                    categories=["prompt_injection"],
                    branches={
                        "heuristics": {
                            "score": 90,
                            "threatLevel": "HIGH",
                            "explanations": ["Matched prompt injection pattern"],
                            "features": {"pattern": "ignore.*instructions"},
                        },
                        "semantic": {
                            "score": 85,
                            "attackSimilarity": 0.95,
                            "safeSimilarity": 0.05,
                            "matchedCategory": "jailbreak_v2",
                        },
                        "pii": {
                            "detected": True,
                            "entityCount": 2,
                            "categories": ["EMAIL", "PHONE_NUMBER"],
                        },
                        "llmGuard": {
                            "score": 80,
                            "verdict": "BLOCK",
                            "modelUsed": "llm-safety-v2",
                        },
                        "contentMod": {
                            "score": 55,
                            "confidence": 0.7,
                            "categories": [
                                {"name": "HATE_SPEECH", "score": 0.8, "triggered": True},
                                {"name": "SELF_HARM", "score": 0.1, "triggered": False},
                            ],
                            "triggeredCategories": ["HATE_SPEECH"],
                            "detectedLanguage": "en",
                            "modelUsed": "content-safety-en-v1",
                            "suggestedAction": "LOG",
                            "actionApplied": "LOG",
                            "processingTimeMs": 45,
                        },
                    },
                    latencyMs=150,
                ),
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        result = client.detect("test")

        assert result.decision == Decision.BLOCKED
        assert result.score == 95
        assert result.confidence == 0.99
        assert result.threat_level == ThreatLevel.CRITICAL
        assert result.latency_ms == 150

        assert result.branches.heuristics is not None
        assert result.branches.heuristics.score == 90
        assert result.branches.heuristics.threat_level == "HIGH"
        assert result.branches.heuristics.explanations[0] == "Matched prompt injection pattern"

        assert result.branches.semantic is not None
        assert result.branches.semantic.attack_similarity == 0.95
        assert result.branches.semantic.matched_category == "jailbreak_v2"

        assert result.branches.pii is not None
        assert result.branches.pii.detected is True
        assert result.branches.pii.entity_count == 2
        assert "EMAIL" in result.branches.pii.categories

        assert result.branches.llm_guard is not None
        assert result.branches.llm_guard.verdict == "BLOCK"

        assert result.branches.content_mod is not None
        assert result.branches.content_mod.suggested_action == "LOG"
        assert result.branches.content_mod.triggered_categories == ["HATE_SPEECH"]

    def test_all_decision_values(self, respx_mock: respx.MockRouter) -> None:
        """All possible decision enum values are parseable."""
        # Test non-SANITIZED decisions (SANITIZED requires sanitizedText)
        decisions = ["ALLOWED", "BLOCKED"]

        for decision_str in decisions:
            with respx.mock(assert_all_mocked=True, assert_all_called=False) as mock:
                mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
                    return_value=Response(
                        200,
                        json=build_detection_response(
                            requestId=f"req_{decision_str.lower()}",
                            decision=decision_str,
                            score=50,
                        ),
                    )
                )

                client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
                result = client.detect("test")

                assert result.decision == Decision(decision_str)

    def test_sanitized_decision_requires_text(self, respx_mock: respx.MockRouter) -> None:
        """SANITIZED decision requires sanitizedText field."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_detection_response(
                    requestId="req_sanitized",
                    decision="SANITIZED",
                    score=50,
                    sanitizedText="Cleaned content",
                ),
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        result = client.detect("test")

        assert result.decision == Decision.SANITIZED
        assert result.sanitized_text == "Cleaned content"

    @pytest.mark.parametrize(
        "score,threat_level",
        [
            (10, ThreatLevel.LOW),
            (90, ThreatLevel.HIGH),
        ],
    )
    def test_threat_level_from_response(self, score: int, threat_level: ThreatLevel) -> None:
        """Threat level is parsed from the API response."""
        with respx.mock(assert_all_mocked=True, assert_all_called=False) as mock:
            mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
                return_value=Response(
                    200,
                    json=build_detection_response(
                        requestId="req_threat_level",
                        decision="ALLOWED",
                        score=score,
                        threatLevel=threat_level.value,
                    ),
                )
            )

            client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
            result = client.detect("test")

            assert result.threat_level == threat_level

    def test_sanitized_response_with_text(self, respx_mock: respx.MockRouter) -> None:
        """SANITIZED decision includes sanitizedText field."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_detection_response(
                    requestId="req_sanitized",
                    decision="SANITIZED",
                    score=45,
                    threatLevel="MEDIUM",
                    sanitizedText="Hello, my email is [REDACTED]",
                    branches={
                        "pii": {
                            "detected": True,
                            "entityCount": 1,
                            "categories": ["EMAIL"],
                        }
                    },
                ),
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        result = client.detect("test")

        assert result.decision == Decision.SANITIZED
        assert result.sanitized_text == "Hello, my email is [REDACTED]"
        assert result.is_sanitized is True

    def test_empty_branches(self, respx_mock: respx.MockRouter) -> None:
        """Response with empty branches object."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_detection_response(
                    requestId="req_empty_branches",
                    decision="ALLOWED",
                    score=5,
                    branches={},
                ),
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        result = client.detect("test")

        assert result.branches.heuristics is None
        assert result.branches.semantic is None
        assert result.branches.pii is None
        assert result.branches.llm_guard is None


class TestBatchResponseContract:
    """Contract tests for /v1/guard/batch response schema."""

    def test_batch_all_success(self, respx_mock: respx.MockRouter) -> None:
        """Batch response with all items successful."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/batch").mock(
            return_value=Response(
                200,
                json={
                    "items": [
                        {
                            "index": 0,
                            "ok": True,
                            "response": build_detection_response(
                                requestId="rb0",
                                decision="ALLOWED",
                                score=5,
                            ),
                        },
                        {
                            "index": 1,
                            "ok": True,
                            "response": build_detection_response(
                                requestId="rb1",
                                decision="BLOCKED",
                                score=90,
                                threatLevel="HIGH",
                            ),
                        },
                        {
                            "index": 2,
                            "ok": True,
                            "response": build_detection_response(
                                requestId="rb2",
                                decision="SANITIZED",
                                score=50,
                                threatLevel="MEDIUM",
                                sanitizedText="redacted",
                            ),
                        },
                    ],
                },
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        items = [BatchItem(text="a"), BatchItem(text="b"), BatchItem(text="c")]
        result = client.batch(items)

        assert result.total == 3
        assert result.succeeded == 3
        assert result.failed == 0
        assert result.all_succeeded is True
        assert result.has_failures is False

    def test_batch_with_failures(self, respx_mock: respx.MockRouter) -> None:
        """Batch response with mixed success and failure."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/batch").mock(
            return_value=Response(
                200,
                json={
                    "items": [
                        {
                            "index": 0,
                            "ok": True,
                            "response": build_detection_response(
                                requestId="rb0",
                                decision="ALLOWED",
                                score=5,
                            ),
                        },
                        {
                            "index": 1,
                            "ok": False,
                            "error": {"code": "TEXT_TOO_LONG", "message": "Exceeds 100k chars"},
                        },
                        {
                            "index": 2,
                            "ok": False,
                            "error": {"code": "INVALID_ENCODING", "message": "Not valid UTF-8"},
                        },
                    ],
                },
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        items = [BatchItem(text="ok"), BatchItem(text="x" * 200000), BatchItem(text="\xff")]
        result = client.batch(items)

        assert result.has_failures is True
        assert len(result.successful_items()) == 1
        assert len(result.failed_items()) == 2

        failed = result.failed_items()
        assert failed[0].error is not None
        assert failed[0].error.code == "TEXT_TOO_LONG"
        assert failed[1].error is not None
        assert failed[1].error.code == "INVALID_ENCODING"


class TestErrorResponseContract:
    """Contract tests for error response schemas."""

    def test_401_authentication_error(self, respx_mock: respx.MockRouter) -> None:
        """401 Unauthorized response format."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                401,
                json={
                    "error": "Invalid API key",
                    "code": "INVALID_API_KEY",
                },
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)

        with pytest.raises(VigilAuthenticationError) as exc_info:
            client.detect("test")

        assert "Invalid API key" in str(exc_info.value)

    def test_400_validation_error_with_details(self, respx_mock: respx.MockRouter) -> None:
        """400 Bad Request with validation details."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                400,
                json={
                    "error": "Validation failed",
                    "details": [
                        {"path": "prompt", "message": "Prompt is required"},
                        {"path": "metadata.userId", "message": "Must be string"},
                    ],
                },
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)

        with pytest.raises(VigilValidationError) as exc_info:
            client.detect("")

        assert len(exc_info.value.errors) == 2
        assert exc_info.value.errors[0]["path"] == "prompt"

    def test_429_rate_limit_with_retry_info(self, respx_mock: respx.MockRouter) -> None:
        """429 Rate Limit response with retry information."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                429,
                json={
                    "error": "Rate limit exceeded",
                    "retryAfter": 60,
                    "limit": 1000,
                    "remaining": 0,
                    "resetAt": "2024-01-15T11:00:00Z",
                },
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL, max_retries=0)

        with pytest.raises(VigilRateLimitError) as exc_info:
            client.detect("test")

        assert exc_info.value.retry_after == 60
        assert exc_info.value.limit == 1000

    def test_500_service_error(self, respx_mock: respx.MockRouter) -> None:
        """500 Internal Server Error response."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                500,
                json={
                    "error": "Internal server error",
                    "code": "INTERNAL_ERROR",
                    "requestId": "req_error_500",
                },
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL, max_retries=0)

        with pytest.raises(VigilServiceError):
            client.detect("test")

    def test_503_service_unavailable(self, respx_mock: respx.MockRouter) -> None:
        """503 Service Unavailable response."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                503,
                json={
                    "error": "Service temporarily unavailable",
                    "code": "SERVICE_UNAVAILABLE",
                },
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL, max_retries=0)

        with pytest.raises(VigilServiceError):
            client.detect("test")


class TestRequestContract:
    """Contract tests for request payloads."""

    def test_detect_request_payload(self, respx_mock: respx.MockRouter) -> None:
        """Detect request sends correct payload structure."""
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_detection_response(requestId="req_1", decision="ALLOWED", score=0),
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        client.detect("Test text", metadata={"user_id": "u123", "session": "s456"})

        request = route.calls[0].request
        import json

        body = json.loads(request.content)

        assert body["prompt"] == "Test text"
        assert body["metadata"]["user_id"] == "u123"
        assert body["metadata"]["session"] == "s456"
        assert body["mode"] == "full"

    def test_detect_output_request_payload(self, respx_mock: respx.MockRouter) -> None:
        """Detect output request sends correct payload structure."""
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/output").mock(
            return_value=Response(
                200,
                json=build_detection_response(requestId="req_1", decision="ALLOWED", score=0),
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        client.detect_output("LLM response", original_prompt="User question")

        request = route.calls[0].request
        import json

        body = json.loads(request.content)

        assert body["output"] == "LLM response"
        assert body["originalPrompt"] == "User question"
        assert body["mode"] == "full"

    def test_analyze_request_payload(self, respx_mock: respx.MockRouter) -> None:
        """Analyze request sends correct payload structure."""
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/analyze").mock(
            return_value=Response(
                200,
                json=build_detection_response(requestId="req_1", decision="ALLOWED", score=0),
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        client.analyze("Test", Source.USER_INPUT)

        request = route.calls[0].request
        import json

        body = json.loads(request.content)

        assert body["text"] == "Test"
        assert body["source"] == "user_input"
        assert body["mode"] == "full"

    def test_batch_request_payload(self, respx_mock: respx.MockRouter) -> None:
        """Batch request sends correct payload structure."""
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/batch").mock(
            return_value=Response(
                200,
                json={
                    "items": [
                        {
                            "index": 0,
                            "ok": True,
                            "response": build_detection_response(
                                requestId="r0", decision="ALLOWED", score=0
                            ),
                        },
                        {
                            "index": 1,
                            "ok": True,
                            "response": build_detection_response(
                                requestId="r1", decision="ALLOWED", score=0
                            ),
                        },
                    ],
                },
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        items = [
            BatchItem(text="Item 1"),
            BatchItem(text="Item 2", source=Source.MODEL_OUTPUT, metadata={"key": "value"}),
        ]
        client.batch(items)

        request = route.calls[0].request
        import json

        body = json.loads(request.content)

        assert len(body["items"]) == 2
        assert body["items"][0]["text"] == "Item 1"
        assert body["items"][1]["text"] == "Item 2"
        assert body["items"][1]["source"] == "model_output"
        assert body["items"][1]["metadata"]["key"] == "value"
        assert body["items"][0]["mode"] == "full"

    def test_idempotency_key_header(self, respx_mock: respx.MockRouter) -> None:
        """Idempotency key is sent in header."""
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_detection_response(requestId="req_1", decision="ALLOWED", score=0),
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        client.detect("Test", idempotency_key="custom_key_123")

        request = route.calls[0].request
        assert request.headers.get("X-Idempotency-Key") == "custom_key_123"

    def test_auto_generated_idempotency_key(self, respx_mock: respx.MockRouter) -> None:
        """Idempotency key is auto-generated if not provided."""
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_detection_response(requestId="req_1", decision="ALLOWED", score=0),
            )
        )

        client = Vigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)
        client.detect("Test")

        request = route.calls[0].request
        idem_key = request.headers.get("X-Idempotency-Key")
        assert idem_key is not None
        assert len(idem_key) > 0


class TestAsyncContract:
    """Contract tests for async client."""

    @pytest.mark.asyncio
    async def test_async_detect_contract(self, respx_mock: respx.MockRouter) -> None:
        """Async detect follows same contract as sync."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").mock(
            return_value=Response(
                200,
                json=build_detection_response(
                    requestId="req_async",
                    decision="BLOCKED",
                    score=85,
                    threatLevel="HIGH",
                    branches={
                        "heuristics": {"score": 85, "threatLevel": "HIGH", "explanations": []},
                    },
                ),
            )
        )

        async with AsyncVigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL) as client:
            result = await client.detect("test")

        assert result.decision == Decision.BLOCKED
        assert result.score == 85
        assert result.branches.heuristics is not None

    @pytest.mark.asyncio
    async def test_async_batch_contract(self, respx_mock: respx.MockRouter) -> None:
        """Async batch follows same contract as sync."""
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/batch").mock(
            return_value=Response(
                200,
                json={
                    "items": [
                        {
                            "index": 0,
                            "ok": True,
                            "response": build_detection_response(
                                requestId="r0", decision="ALLOWED", score=5
                            ),
                        },
                        {
                            "index": 1,
                            "ok": True,
                            "response": build_detection_response(
                                requestId="r1",
                                decision="BLOCKED",
                                score=90,
                                threatLevel="HIGH",
                            ),
                        },
                    ],
                },
            )
        )

        async with AsyncVigil(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL) as client:
            items = [BatchItem(text="a"), BatchItem(text="b")]
            result = await client.batch(items)

        assert result.total == 2
        assert result.all_succeeded is True
