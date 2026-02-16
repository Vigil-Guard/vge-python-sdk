"""Unit tests for async HTTP transport and retry logic."""

from __future__ import annotations

from unittest import mock

import httpx
import pytest
import respx

from vigil import (
    ClientConfig,
    VigilAuthenticationError,
    VigilConnectionError,
    VigilRateLimitError,
    VigilRetryBudgetExceeded,
    VigilServiceError,
    VigilTimeoutError,
    VigilValidationError,
)
from vigil._async_http import AsyncHttpTransport
from vigil._async_retry import AsyncRetryConfig, AsyncRetryHandler

DUMMY_BASE_URL = "https://api.vigilguard.test.local"
DUMMY_API_KEY = "vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


@pytest.fixture
def config() -> ClientConfig:
    return ClientConfig(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)


@pytest.fixture
def transport(config: ClientConfig) -> AsyncHttpTransport:
    return AsyncHttpTransport(config)


@pytest.fixture
def handler() -> AsyncRetryHandler:
    return AsyncRetryHandler(max_retries=3)


class TestAsyncHttpTransport:
    async def test_successful_get_request(
        self, respx_mock: respx.MockRouter, transport: AsyncHttpTransport
    ) -> None:
        respx_mock.get(f"{DUMMY_BASE_URL}/v1/health").respond(json={"status": "ok"})

        result = await transport.request("GET", "/v1/health")
        assert result == {"status": "ok"}

    async def test_successful_post_request(
        self, respx_mock: respx.MockRouter, transport: AsyncHttpTransport
    ) -> None:
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").respond(
            json={"decision": "ALLOWED", "score": 10}
        )

        result = await transport.request("POST", "/v1/guard/input", json={"prompt": "hello"})
        assert result["decision"] == "ALLOWED"

    async def test_idempotency_key_header(
        self, respx_mock: respx.MockRouter, transport: AsyncHttpTransport
    ) -> None:
        route = respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").respond(
            json={"decision": "ALLOWED"}
        )

        await transport.request(
            "POST",
            "/v1/guard/input",
            json={"prompt": "test"},
            idempotency_key="idem_abc123",
        )

        request = route.calls[0].request
        assert request.headers.get("X-Idempotency-Key") == "idem_abc123"

    async def test_authorization_header(
        self, respx_mock: respx.MockRouter, transport: AsyncHttpTransport
    ) -> None:
        route = respx_mock.get(f"{DUMMY_BASE_URL}/v1/health").respond(json={"status": "ok"})

        await transport.request("GET", "/v1/health")

        request = route.calls[0].request
        assert request.headers.get("Authorization") == f"Bearer {DUMMY_API_KEY}"

    async def test_user_agent_header(
        self, respx_mock: respx.MockRouter, transport: AsyncHttpTransport
    ) -> None:
        route = respx_mock.get(f"{DUMMY_BASE_URL}/v1/health").respond(json={"status": "ok"})

        await transport.request("GET", "/v1/health")

        request = route.calls[0].request
        assert "vigil-python" in request.headers.get("User-Agent", "")

    async def test_context_manager(
        self, respx_mock: respx.MockRouter, config: ClientConfig
    ) -> None:
        respx_mock.get(f"{DUMMY_BASE_URL}/v1/health").respond(json={"status": "ok"})

        async with AsyncHttpTransport(config) as transport:
            result = await transport.request("GET", "/v1/health")
            assert result["status"] == "ok"


class TestAsyncHttpTransportErrors:
    async def test_connection_error(
        self, respx_mock: respx.MockRouter, transport: AsyncHttpTransport
    ) -> None:
        respx_mock.get(f"{DUMMY_BASE_URL}/v1/health").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        with pytest.raises(VigilConnectionError, match="Failed to connect"):
            await transport.request("GET", "/v1/health")

    async def test_timeout_error(
        self, respx_mock: respx.MockRouter, transport: AsyncHttpTransport
    ) -> None:
        respx_mock.get(f"{DUMMY_BASE_URL}/v1/health").mock(
            side_effect=httpx.ReadTimeout("Read timed out")
        )

        with pytest.raises(VigilTimeoutError, match="timed out"):
            await transport.request("GET", "/v1/health")

    async def test_400_validation_error(
        self, respx_mock: respx.MockRouter, transport: AsyncHttpTransport
    ) -> None:
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").respond(
            status_code=400, json={"error": "Validation failed", "details": []}
        )

        with pytest.raises(VigilValidationError):
            await transport.request("POST", "/v1/guard/input", json={"prompt": ""})

    async def test_429_rate_limit_error(
        self, respx_mock: respx.MockRouter, transport: AsyncHttpTransport
    ) -> None:
        respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").respond(
            status_code=429, json={"error": "Rate limit exceeded", "retryAfter": 60}
        )

        with pytest.raises(VigilRateLimitError) as exc_info:
            await transport.request("POST", "/v1/guard/input", json={"prompt": "test"})
        assert exc_info.value.retry_after == 60

    async def test_503_service_error(
        self, respx_mock: respx.MockRouter, transport: AsyncHttpTransport
    ) -> None:
        respx_mock.get(f"{DUMMY_BASE_URL}/v1/health").respond(
            status_code=503, json={"error": "Service unavailable", "retryAfter": 30}
        )

        with pytest.raises(VigilServiceError) as exc_info:
            await transport.request("GET", "/v1/health")
        assert exc_info.value.retry_after == 30


class TestAsyncRetryHandler:
    async def test_successful_first_attempt(
        self, transport: AsyncHttpTransport, handler: AsyncRetryHandler
    ) -> None:
        with mock.patch.object(transport, "request", return_value={"status": "ok"}) as mock_request:
            result = await handler.execute(transport, "GET", "/health")

        assert result == {"status": "ok"}
        assert mock_request.call_count == 1

    async def test_retry_on_connection_error(
        self, transport: AsyncHttpTransport, handler: AsyncRetryHandler
    ) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = [
                VigilConnectionError("Connection failed"),
                {"status": "ok"},
            ]

            with mock.patch("vigil._async_retry.asyncio.sleep", return_value=None):
                result = await handler.execute(transport, "GET", "/health")

        assert result == {"status": "ok"}
        assert mock_request.call_count == 2

    async def test_retry_on_timeout_error(
        self, transport: AsyncHttpTransport, handler: AsyncRetryHandler
    ) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = [
                VigilTimeoutError("Timeout"),
                {"status": "ok"},
            ]

            with mock.patch("vigil._async_retry.asyncio.sleep", return_value=None):
                result = await handler.execute(transport, "GET", "/health")

        assert result == {"status": "ok"}
        assert mock_request.call_count == 2

    async def test_retry_on_rate_limit(
        self, transport: AsyncHttpTransport, handler: AsyncRetryHandler
    ) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = [
                VigilRateLimitError("Rate limited", retry_after=1),
                {"status": "ok"},
            ]

            with mock.patch("vigil._async_retry.asyncio.sleep", return_value=None) as mock_sleep:
                result = await handler.execute(transport, "GET", "/health")

        assert result == {"status": "ok"}
        mock_sleep.assert_called_once()
        assert mock_sleep.call_args[0][0] == 1.0

    async def test_retry_on_service_error(
        self, transport: AsyncHttpTransport, handler: AsyncRetryHandler
    ) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = [
                VigilServiceError("Service down"),
                {"status": "ok"},
            ]

            with mock.patch("vigil._async_retry.asyncio.sleep", return_value=None):
                result = await handler.execute(transport, "GET", "/health")

        assert result == {"status": "ok"}
        assert mock_request.call_count == 2

    async def test_no_retry_on_auth_error(
        self, transport: AsyncHttpTransport, handler: AsyncRetryHandler
    ) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = VigilAuthenticationError("Invalid key")

            with pytest.raises(VigilAuthenticationError):
                await handler.execute(transport, "GET", "/health")

        assert mock_request.call_count == 1

    async def test_no_retry_on_validation_error(
        self, transport: AsyncHttpTransport, handler: AsyncRetryHandler
    ) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = VigilValidationError("Bad input")

            with pytest.raises(VigilValidationError):
                await handler.execute(transport, "GET", "/health")

        assert mock_request.call_count == 1

    async def test_max_retries_exhausted(
        self, transport: AsyncHttpTransport, handler: AsyncRetryHandler
    ) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = VigilConnectionError("Always fails")

            with (
                mock.patch("vigil._async_retry.asyncio.sleep", return_value=None),
                pytest.raises(VigilConnectionError),
            ):
                await handler.execute(transport, "GET", "/health")

        assert mock_request.call_count == 4  # 1 initial + 3 retries

    async def test_retry_budget_exceeded(self, transport: AsyncHttpTransport) -> None:
        handler = AsyncRetryHandler(max_retries=10, retry_budget=0.1)

        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = VigilConnectionError("Always fails")

            with (
                mock.patch("vigil._async_retry.asyncio.sleep", return_value=None),
                pytest.raises(VigilRetryBudgetExceeded) as exc_info,
            ):
                await handler.execute(transport, "GET", "/health")

        assert mock_request.call_count < 10
        assert exc_info.value.retry_budget == 0.1

    async def test_idempotency_key_preserved(
        self, transport: AsyncHttpTransport, handler: AsyncRetryHandler
    ) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = [
                VigilConnectionError("Fail 1"),
                {"status": "ok"},
            ]

            with mock.patch("vigil._async_retry.asyncio.sleep", return_value=None):
                await handler.execute(
                    transport,
                    "POST",
                    "/v1/guard/input",
                    idempotency_key="idem_test123",
                )

        for call in mock_request.call_args_list:
            assert call.kwargs.get("idempotency_key") == "idem_test123"


class TestAsyncRetryConfig:
    def test_create_handler(self) -> None:
        config = AsyncRetryConfig(max_retries=5, base_delay=2.0)
        handler = config.create_handler()

        assert isinstance(handler, AsyncRetryHandler)
        assert handler.max_retries == 5
        assert handler.base_delay == 2.0
