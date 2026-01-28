"""Unit tests for HTTP transport."""

from __future__ import annotations

import httpx
import pytest
import respx

from vigil import (
    ClientConfig,
    VigilConnectionError,
    VigilRateLimitError,
    VigilServiceError,
    VigilTimeoutError,
    VigilValidationError,
)
from vigil._http import HttpTransport, generate_idempotency_key

DUMMY_BASE_URL = "https://api.vigilguard.test.local"
DUMMY_API_KEY = "vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


@pytest.fixture
def config() -> ClientConfig:
    return ClientConfig(
        api_key=DUMMY_API_KEY,
        base_url=DUMMY_BASE_URL,
    )


@pytest.fixture
def transport(config: ClientConfig) -> HttpTransport:
    return HttpTransport(config)


@pytest.mark.unit
class TestHttpTransport:
    """Tests for HttpTransport class."""

    def test_successful_get_request(
        self, respx_mock: respx.MockRouter, transport: HttpTransport
    ) -> None:
        respx_mock.get(f"{DUMMY_BASE_URL}/v1/health").respond(json={"status": "ok"})

        result = transport.request("GET", "/v1/health")
        assert result == {"status": "ok"}

    def test_successful_post_request(
        self, respx_mock: respx.MockRouter, transport: HttpTransport
    ) -> None:
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").respond(
            json={"decision": "ALLOWED", "score": 10}
        )

        result = transport.request("POST", "/v1/guard/input", json={"prompt": "hello"})
        assert result["decision"] == "ALLOWED"

    def test_idempotency_key_header(
        self, respx_mock: respx.MockRouter, transport: HttpTransport
    ) -> None:
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").respond(
            json={"decision": "ALLOWED"}
        )

        transport.request(
            "POST",
            "/v1/guard/input",
            json={"prompt": "test"},
            idempotency_key="idem_abc123",
        )

        assert route.called
        request = route.calls[0].request
        assert request.headers.get("X-Idempotency-Key") == "idem_abc123"

    def test_custom_headers(self, respx_mock: respx.MockRouter, transport: HttpTransport) -> None:
        route = respx_mock.get(f"{DUMMY_BASE_URL}/v1/health").respond(json={"status": "ok"})

        transport.request(
            "GET",
            "/v1/health",
            headers={"X-Custom-Header": "custom-value"},
        )

        assert route.called
        request = route.calls[0].request
        assert request.headers.get("X-Custom-Header") == "custom-value"

    def test_authorization_header(
        self, respx_mock: respx.MockRouter, transport: HttpTransport
    ) -> None:
        route = respx_mock.get(f"{DUMMY_BASE_URL}/v1/health").respond(json={"status": "ok"})

        transport.request("GET", "/v1/health")

        request = route.calls[0].request
        assert request.headers.get("Authorization") == f"Bearer {DUMMY_API_KEY}"

    def test_user_agent_header(
        self, respx_mock: respx.MockRouter, transport: HttpTransport
    ) -> None:
        route = respx_mock.get(f"{DUMMY_BASE_URL}/v1/health").respond(json={"status": "ok"})

        transport.request("GET", "/v1/health")

        request = route.calls[0].request
        assert "vigil-python" in request.headers.get("User-Agent", "")


@pytest.mark.unit
class TestHttpTransportErrors:
    """Tests for HTTP transport error handling."""

    def test_connection_error(self, respx_mock: respx.MockRouter, transport: HttpTransport) -> None:
        respx_mock.get(f"{DUMMY_BASE_URL}/v1/health").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        with pytest.raises(VigilConnectionError) as exc_info:
            transport.request("GET", "/v1/health")
        assert "Failed to connect" in str(exc_info.value)

    def test_timeout_error(self, respx_mock: respx.MockRouter, transport: HttpTransport) -> None:
        respx_mock.get(f"{DUMMY_BASE_URL}/v1/health").mock(
            side_effect=httpx.ReadTimeout("Read timed out")
        )

        with pytest.raises(VigilTimeoutError) as exc_info:
            transport.request("GET", "/v1/health")
        assert "timed out" in str(exc_info.value).lower()

    def test_400_validation_error(
        self, respx_mock: respx.MockRouter, transport: HttpTransport
    ) -> None:
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").respond(
            status_code=400,
            json={"error": "Validation failed", "details": []},
        )

        with pytest.raises(VigilValidationError):
            transport.request("POST", "/v1/guard/input", json={"prompt": ""})

    def test_429_rate_limit_error(
        self, respx_mock: respx.MockRouter, transport: HttpTransport
    ) -> None:
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").respond(
            status_code=429,
            json={"error": "Rate limit exceeded", "retryAfter": 60},
        )

        with pytest.raises(VigilRateLimitError) as exc_info:
            transport.request("POST", "/v1/guard/input", json={"prompt": "test"})
        assert exc_info.value.retry_after == 60

    def test_503_service_error(
        self, respx_mock: respx.MockRouter, transport: HttpTransport
    ) -> None:
        respx_mock.get(f"{DUMMY_BASE_URL}/v1/health").respond(
            status_code=503,
            json={"error": "Service unavailable", "retryAfter": 30},
        )

        with pytest.raises(VigilServiceError) as exc_info:
            transport.request("GET", "/v1/health")
        assert exc_info.value.retry_after == 30

    def test_request_id_extraction(
        self, respx_mock: respx.MockRouter, transport: HttpTransport
    ) -> None:
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").respond(
            status_code=400,
            json={"error": "Bad request"},
            headers={"X-Request-Id": "req_xyz789"},
        )

        with pytest.raises(VigilValidationError) as exc_info:
            transport.request("POST", "/v1/guard/input", json={})
        assert exc_info.value.request_id == "req_xyz789"


@pytest.mark.unit
class TestHttpTransportLifecycle:
    """Tests for HTTP transport lifecycle management."""

    def test_close(self, config: ClientConfig) -> None:
        transport = HttpTransport(config)
        transport.close()
        assert transport._client is None

    def test_context_manager(self, respx_mock: respx.MockRouter, config: ClientConfig) -> None:
        respx_mock.get(f"{DUMMY_BASE_URL}/v1/health").respond(json={"status": "ok"})

        with HttpTransport(config) as transport:
            result = transport.request("GET", "/v1/health")
            assert result["status"] == "ok"


@pytest.mark.unit
class TestIdempotencyKey:
    """Tests for idempotency key generation."""

    def test_generate_idempotency_key_format(self) -> None:
        key = generate_idempotency_key()
        assert key.startswith("idem_")
        assert len(key) == 37  # "idem_" + 32 hex chars

    def test_generate_idempotency_key_unique(self) -> None:
        keys = {generate_idempotency_key() for _ in range(100)}
        assert len(keys) == 100
