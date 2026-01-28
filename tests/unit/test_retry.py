"""Unit tests for retry logic."""

from __future__ import annotations

from unittest import mock

import pytest

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
from vigil._http import HttpTransport
from vigil._retry import (
    DEFAULT_BASE_DELAY,
    DEFAULT_MAX_DELAY,
    RetryConfig,
    RetryHandler,
    parse_retry_after,
)

DUMMY_BASE_URL = "https://api.vigilguard.test.local"
DUMMY_API_KEY = "vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


@pytest.fixture
def config() -> ClientConfig:
    return ClientConfig(api_key=DUMMY_API_KEY, base_url=DUMMY_BASE_URL)


@pytest.fixture
def transport(config: ClientConfig) -> HttpTransport:
    return HttpTransport(config)


@pytest.fixture
def handler() -> RetryHandler:
    return RetryHandler(max_retries=3)


@pytest.mark.unit
class TestRetryHandler:
    """Tests for RetryHandler class."""

    def test_successful_first_attempt(
        self, transport: HttpTransport, handler: RetryHandler
    ) -> None:
        with mock.patch.object(transport, "request", return_value={"status": "ok"}) as mock_request:
            result = handler.execute(transport, "GET", "/health")

        assert result == {"status": "ok"}
        assert mock_request.call_count == 1

    def test_retry_on_connection_error(
        self, transport: HttpTransport, handler: RetryHandler
    ) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = [
                VigilConnectionError("Connection failed"),
                {"status": "ok"},
            ]

            with mock.patch("vigil._retry.time.sleep"):
                result = handler.execute(transport, "GET", "/health")

        assert result == {"status": "ok"}
        assert mock_request.call_count == 2

    def test_retry_on_timeout_error(self, transport: HttpTransport, handler: RetryHandler) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = [
                VigilTimeoutError("Timeout"),
                {"status": "ok"},
            ]

            with mock.patch("vigil._retry.time.sleep"):
                result = handler.execute(transport, "GET", "/health")

        assert result == {"status": "ok"}
        assert mock_request.call_count == 2

    def test_retry_on_rate_limit(self, transport: HttpTransport, handler: RetryHandler) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = [
                VigilRateLimitError("Rate limited", retry_after=1),
                {"status": "ok"},
            ]

            with mock.patch("vigil._retry.time.sleep") as mock_sleep:
                result = handler.execute(transport, "GET", "/health")

        assert result == {"status": "ok"}
        mock_sleep.assert_called_once()
        assert mock_sleep.call_args[0][0] == 1.0

    def test_retry_on_service_error(self, transport: HttpTransport, handler: RetryHandler) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = [
                VigilServiceError("Service down"),
                {"status": "ok"},
            ]

            with mock.patch("vigil._retry.time.sleep"):
                result = handler.execute(transport, "GET", "/health")

        assert result == {"status": "ok"}
        assert mock_request.call_count == 2

    def test_no_retry_on_auth_error(self, transport: HttpTransport, handler: RetryHandler) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = VigilAuthenticationError("Invalid key")

            with pytest.raises(VigilAuthenticationError):
                handler.execute(transport, "GET", "/health")

        assert mock_request.call_count == 1

    def test_no_retry_on_validation_error(
        self, transport: HttpTransport, handler: RetryHandler
    ) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = VigilValidationError("Bad input")

            with pytest.raises(VigilValidationError):
                handler.execute(transport, "GET", "/health")

        assert mock_request.call_count == 1

    def test_max_retries_exhausted(self, transport: HttpTransport, handler: RetryHandler) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = VigilConnectionError("Always fails")

            with mock.patch("vigil._retry.time.sleep"), pytest.raises(VigilConnectionError):
                handler.execute(transport, "GET", "/health")

        assert mock_request.call_count == 4  # 1 initial + 3 retries

    def test_idempotency_key_preserved(
        self, transport: HttpTransport, handler: RetryHandler
    ) -> None:
        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = [
                VigilConnectionError("Fail 1"),
                {"status": "ok"},
            ]

            with mock.patch("vigil._retry.time.sleep"):
                handler.execute(
                    transport,
                    "POST",
                    "/v1/guard/input",
                    idempotency_key="idem_test123",
                )

        for call in mock_request.call_args_list:
            assert call.kwargs.get("idempotency_key") == "idem_test123"


@pytest.mark.unit
class TestRetryDelay:
    """Tests for retry delay calculation."""

    def test_exponential_backoff(self) -> None:
        handler = RetryHandler(base_delay=1.0, jitter_factor=0.0)

        with mock.patch("vigil._retry.JITTER_RNG.random", return_value=0):
            delay0 = handler._calculate_delay(0, VigilConnectionError(""))
            delay1 = handler._calculate_delay(1, VigilConnectionError(""))
            delay2 = handler._calculate_delay(2, VigilConnectionError(""))

        assert delay0 == 1.0
        assert delay1 == 2.0
        assert delay2 == 4.0

    def test_max_delay_cap(self) -> None:
        handler = RetryHandler(base_delay=1.0, max_delay=5.0, jitter_factor=0.0)

        with mock.patch("vigil._retry.JITTER_RNG.random", return_value=0):
            delay = handler._calculate_delay(10, VigilConnectionError(""))

        assert delay == 5.0

    def test_retry_after_honored(self) -> None:
        handler = RetryHandler()
        error = VigilRateLimitError("Rate limited", retry_after=120)

        delay = handler._calculate_delay(0, error)
        assert delay == 60.0  # Capped by max_delay

    def test_retry_after_with_low_value(self) -> None:
        handler = RetryHandler(max_delay=60.0)
        error = VigilRateLimitError("Rate limited", retry_after=5)

        delay = handler._calculate_delay(0, error)
        assert delay == 5.0

    def test_jitter_applied(self) -> None:
        handler = RetryHandler(base_delay=1.0, jitter_factor=0.25)

        delays = set()
        for _ in range(10):
            delay = handler._calculate_delay(0, VigilConnectionError(""))
            delays.add(delay)

        assert len(delays) > 1
        assert all(1.0 <= d <= 1.25 for d in delays)


@pytest.mark.unit
class TestRetryBudget:
    """Tests for retry budget enforcement."""

    def test_retry_budget_exceeded(self, transport: HttpTransport) -> None:
        handler = RetryHandler(max_retries=10, retry_budget=0.1)

        with mock.patch.object(transport, "request") as mock_request:
            mock_request.side_effect = VigilConnectionError("Always fails")

            with mock.patch("vigil._retry.time.sleep", return_value=None) as mock_sleep:
                mock_sleep.side_effect = lambda x: None

                with pytest.raises(VigilRetryBudgetExceeded) as exc_info:
                    handler.execute(transport, "GET", "/health")

        assert mock_request.call_count < 10
        assert exc_info.value.retry_budget == 0.1


@pytest.mark.unit
class TestParseRetryAfter:
    """Tests for Retry-After header parsing."""

    def test_parse_integer_seconds(self) -> None:
        assert parse_retry_after("60") == 60.0
        assert parse_retry_after("120") == 120.0
        assert parse_retry_after("0") == 0.0

    def test_parse_float_seconds(self) -> None:
        assert parse_retry_after("30.5") == 30.5

    def test_parse_http_date(self) -> None:
        with mock.patch("vigil._retry.time.time", return_value=0):
            result = parse_retry_after("Thu, 01 Jan 1970 00:01:00 GMT")
        assert result == 60.0

    def test_parse_invalid_returns_none(self) -> None:
        assert parse_retry_after("invalid") is None
        assert parse_retry_after("") is None


@pytest.mark.unit
class TestRetryConfig:
    """Tests for RetryConfig class."""

    def test_default_values(self) -> None:
        config = RetryConfig()
        assert config.max_retries == 3
        assert config.base_delay == DEFAULT_BASE_DELAY
        assert config.max_delay == DEFAULT_MAX_DELAY

    def test_custom_values(self) -> None:
        config = RetryConfig(
            max_retries=5,
            base_delay=1.0,
            max_delay=30.0,
        )
        assert config.max_retries == 5
        assert config.base_delay == 1.0
        assert config.max_delay == 30.0

    def test_create_handler(self) -> None:
        config = RetryConfig(max_retries=5, base_delay=2.0)
        handler = config.create_handler()

        assert isinstance(handler, RetryHandler)
        assert handler.max_retries == 5
        assert handler.base_delay == 2.0
