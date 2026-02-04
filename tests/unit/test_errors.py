"""Unit tests for error hierarchy."""

from __future__ import annotations

import pytest

from vigil import (
    VigilAPIError,
    VigilAuthenticationError,
    VigilBatchPartialFailure,
    VigilConfigurationError,
    VigilConnectionError,
    VigilError,
    VigilLicenseError,
    VigilLicenseExpiredError,
    VigilLicenseRequiredError,
    VigilRateLimitError,
    VigilRetryBudgetExceeded,
    VigilServiceError,
    VigilTimeoutError,
    VigilValidationError,
)
from vigil._errors import _raise_for_status, _should_retry


@pytest.mark.unit
class TestVigilError:
    """Tests for base VigilError."""

    def test_basic_error(self) -> None:
        err = VigilError("Something went wrong")
        assert str(err) == "Something went wrong"
        assert err.message == "Something went wrong"
        assert err.status_code is None
        assert err.request_id is None
        assert err.body is None

    def test_error_with_all_fields(self) -> None:
        err = VigilError(
            "API error",
            status_code=500,
            request_id="req_abc123",
            body={"error": "Internal error"},
        )
        assert err.status_code == 500
        assert err.request_id == "req_abc123"
        assert err.body == {"error": "Internal error"}
        assert "req_abc123" in str(err)

    def test_repr(self) -> None:
        err = VigilError("test", status_code=400, request_id="req_xyz")
        repr_str = repr(err)
        assert "VigilError" in repr_str
        assert "test" in repr_str
        assert "400" in repr_str


@pytest.mark.unit
class TestVigilConfigurationError:
    """Tests for configuration errors."""

    def test_basic_config_error(self) -> None:
        err = VigilConfigurationError("Invalid base_url")
        assert isinstance(err, VigilError)
        assert err.message == "Invalid base_url"
        assert err.status_code is None

    def test_inheritance(self) -> None:
        err = VigilConfigurationError("Invalid config")
        assert isinstance(err, Exception)
        assert isinstance(err, VigilError)


@pytest.mark.unit
class TestVigilAuthenticationError:
    """Tests for authentication errors."""

    def test_default_message(self) -> None:
        err = VigilAuthenticationError()
        assert "API key" in err.message
        assert err.status_code == 401

    def test_custom_message(self) -> None:
        err = VigilAuthenticationError("Token expired", status_code=403, request_id="req_123")
        assert err.message == "Token expired"
        assert err.status_code == 403


@pytest.mark.unit
class TestVigilLicenseError:
    """Tests for base license error."""

    def test_default_message(self) -> None:
        err = VigilLicenseError()
        assert err.message == "License error"
        assert err.status_code == 403
        assert err.error_code is None

    def test_with_error_code(self) -> None:
        err = VigilLicenseError("Custom error", error_code="LICENSE_CUSTOM")
        assert err.error_code == "LICENSE_CUSTOM"
        assert "LICENSE_CUSTOM" in str(err)

    def test_inheritance(self) -> None:
        err = VigilLicenseError()
        assert isinstance(err, VigilError)


@pytest.mark.unit
class TestVigilLicenseExpiredError:
    """Tests for license expired error."""

    def test_default_message(self) -> None:
        err = VigilLicenseExpiredError()
        assert "expired" in err.message.lower()
        assert err.status_code == 403
        assert err.error_code == "LICENSE_EXPIRED"

    def test_custom_message(self) -> None:
        err = VigilLicenseExpiredError("License expired on 2024-01-01", request_id="req_123")
        assert err.message == "License expired on 2024-01-01"
        assert err.request_id == "req_123"

    def test_inheritance(self) -> None:
        err = VigilLicenseExpiredError()
        assert isinstance(err, VigilLicenseError)
        assert isinstance(err, VigilError)


@pytest.mark.unit
class TestVigilLicenseRequiredError:
    """Tests for license required error."""

    def test_default_message(self) -> None:
        err = VigilLicenseRequiredError()
        assert "required" in err.message.lower()
        assert err.status_code == 403
        assert err.error_code == "LICENSE_REQUIRED"

    def test_custom_message(self) -> None:
        err = VigilLicenseRequiredError("No valid license found", request_id="req_456")
        assert err.message == "No valid license found"
        assert err.request_id == "req_456"

    def test_inheritance(self) -> None:
        err = VigilLicenseRequiredError()
        assert isinstance(err, VigilLicenseError)
        assert isinstance(err, VigilError)


@pytest.mark.unit
class TestVigilRateLimitError:
    """Tests for rate limit errors."""

    def test_default_values(self) -> None:
        err = VigilRateLimitError()
        assert err.status_code == 429
        assert err.retry_after == 60
        assert err.limit is None
        assert err.reset_at is None

    def test_with_retry_info(self) -> None:
        err = VigilRateLimitError(
            "Too many requests",
            retry_after=120,
            limit=100,
            reset_at="2024-01-15T12:00:00Z",
        )
        assert err.retry_after == 120
        assert err.limit == 100
        assert err.reset_at == "2024-01-15T12:00:00Z"
        assert "120s" in str(err)


@pytest.mark.unit
class TestVigilValidationError:
    """Tests for validation errors."""

    def test_basic_validation_error(self) -> None:
        err = VigilValidationError("Invalid input")
        assert err.status_code == 400
        assert err.errors == []

    def test_with_error_details(self) -> None:
        err = VigilValidationError(
            "Validation failed",
            errors=[
                {"path": "text", "message": "Required"},
                {"path": "source", "message": "Invalid value"},
            ],
            status_code=422,
        )
        assert len(err.errors) == 2
        assert "text" in str(err)
        assert "Required" in str(err)


@pytest.mark.unit
class TestVigilAPIError:
    """Tests for generic API errors."""

    def test_basic_api_error(self) -> None:
        err = VigilAPIError("Not found", status_code=404)
        assert err.status_code == 404
        assert isinstance(err, VigilError)


@pytest.mark.unit
class TestVigilServiceError:
    """Tests for service errors."""

    def test_default_values(self) -> None:
        err = VigilServiceError()
        assert err.status_code == 503
        assert "unavailable" in err.message.lower()
        assert err.retry_after is None

    def test_with_retry_after(self) -> None:
        err = VigilServiceError("Service down", retry_after=30, status_code=502)
        assert err.retry_after == 30
        assert err.status_code == 502


@pytest.mark.unit
class TestVigilConnectionError:
    """Tests for connection errors."""

    def test_basic_connection_error(self) -> None:
        err = VigilConnectionError("Network unreachable")
        assert isinstance(err, VigilError)
        assert err.status_code is None


@pytest.mark.unit
class TestVigilTimeoutError:
    """Tests for timeout errors."""

    def test_default_timeout_error(self) -> None:
        err = VigilTimeoutError()
        assert "timed out" in err.message.lower()
        assert err.timeout is None

    def test_with_timeout_value(self) -> None:
        err = VigilTimeoutError("Request timed out", timeout=30.0)
        assert err.timeout == 30.0
        assert "30.0s" in str(err)


@pytest.mark.unit
class TestVigilBatchPartialFailure:
    """Tests for batch partial failure."""

    def test_default_values(self) -> None:
        err = VigilBatchPartialFailure()
        assert err.successful == []
        assert err.failed == []

    def test_with_results(self) -> None:
        err = VigilBatchPartialFailure(
            "Batch partially failed",
            successful=[{"index": 0, "result": "ok"}],
            failed=[{"index": 1, "error": "validation"}],
        )
        assert len(err.successful) == 1
        assert len(err.failed) == 1
        assert "1 succeeded" in str(err)
        assert "1 failed" in str(err)


@pytest.mark.unit
class TestVigilRetryBudgetExceeded:
    """Tests for retry budget error."""

    def test_attributes(self) -> None:
        err = VigilRetryBudgetExceeded(retry_budget=10.0, elapsed=5.0, next_delay=6.0)
        assert err.retry_budget == 10.0
        assert err.elapsed == 5.0
        assert err.next_delay == 6.0


@pytest.mark.unit
class TestRaiseForStatus:
    """Tests for _raise_for_status function."""

    def test_400_raises_validation_error(self) -> None:
        with pytest.raises(VigilValidationError) as exc_info:
            _raise_for_status(400, {"error": "Bad request", "details": []}, "req_123")
        assert exc_info.value.status_code == 400
        assert exc_info.value.request_id == "req_123"

    def test_401_raises_auth_error(self) -> None:
        with pytest.raises(VigilAuthenticationError) as exc_info:
            _raise_for_status(401, {"error": "Unauthorized"}, "req_123")
        assert exc_info.value.status_code == 401

    def test_403_raises_auth_error(self) -> None:
        with pytest.raises(VigilAuthenticationError) as exc_info:
            _raise_for_status(403, {"error": "Forbidden"}, "req_123")
        assert exc_info.value.status_code == 403

    def test_403_license_expired_raises_license_expired_error(self) -> None:
        with pytest.raises(VigilLicenseExpiredError) as exc_info:
            _raise_for_status(
                403,
                {"error": "LICENSE_EXPIRED", "message": "Your license has expired"},
                "req_123",
            )
        assert exc_info.value.status_code == 403
        assert exc_info.value.error_code == "LICENSE_EXPIRED"
        assert exc_info.value.request_id == "req_123"

    def test_403_license_required_raises_license_required_error(self) -> None:
        with pytest.raises(VigilLicenseRequiredError) as exc_info:
            _raise_for_status(
                403,
                {"error": "LICENSE_REQUIRED", "message": "A valid license is required"},
                "req_123",
            )
        assert exc_info.value.status_code == 403
        assert exc_info.value.error_code == "LICENSE_REQUIRED"

    def test_404_raises_api_error(self) -> None:
        with pytest.raises(VigilAPIError) as exc_info:
            _raise_for_status(404, {"error": "Not found"}, "req_123")
        assert exc_info.value.status_code == 404

    def test_422_raises_validation_error(self) -> None:
        with pytest.raises(VigilValidationError) as exc_info:
            _raise_for_status(
                422,
                {"error": "Unprocessable", "details": [{"path": "x", "message": "y"}]},
                "req_123",
            )
        assert exc_info.value.status_code == 422

    def test_429_raises_rate_limit_error(self) -> None:
        with pytest.raises(VigilRateLimitError) as exc_info:
            _raise_for_status(
                429, {"error": "Too many", "retryAfter": 120, "limit": 100}, "req_123"
            )
        assert exc_info.value.retry_after == 120
        assert exc_info.value.limit == 100

    def test_500_raises_service_error(self) -> None:
        with pytest.raises(VigilServiceError) as exc_info:
            _raise_for_status(500, {"error": "Internal error"}, "req_123")
        assert exc_info.value.status_code == 500

    def test_503_raises_service_error_with_retry(self) -> None:
        with pytest.raises(VigilServiceError) as exc_info:
            _raise_for_status(503, {"error": "Unavailable", "retryAfter": 60}, "req_123")
        assert exc_info.value.retry_after == 60

    def test_unknown_4xx_raises_api_error(self) -> None:
        with pytest.raises(VigilAPIError) as exc_info:
            _raise_for_status(418, {"error": "I'm a teapot"}, "req_123")
        assert exc_info.value.status_code == 418


@pytest.mark.unit
class TestShouldRetry:
    """Tests for _should_retry function."""

    def test_connection_error_retryable(self) -> None:
        assert _should_retry(VigilConnectionError("Network error")) is True

    def test_timeout_error_retryable(self) -> None:
        assert _should_retry(VigilTimeoutError("Timeout")) is True

    def test_rate_limit_retryable(self) -> None:
        assert _should_retry(VigilRateLimitError()) is True

    def test_service_error_retryable(self) -> None:
        assert _should_retry(VigilServiceError()) is True

    def test_auth_error_not_retryable(self) -> None:
        assert _should_retry(VigilAuthenticationError()) is False

    def test_license_error_not_retryable(self) -> None:
        assert _should_retry(VigilLicenseError()) is False

    def test_license_expired_error_not_retryable(self) -> None:
        assert _should_retry(VigilLicenseExpiredError()) is False

    def test_license_required_error_not_retryable(self) -> None:
        assert _should_retry(VigilLicenseRequiredError()) is False

    def test_validation_error_not_retryable(self) -> None:
        assert _should_retry(VigilValidationError("Bad input")) is False

    def test_api_error_not_retryable(self) -> None:
        assert _should_retry(VigilAPIError("Not found", status_code=404)) is False

    def test_config_error_not_retryable(self) -> None:
        assert _should_retry(VigilConfigurationError("Bad config")) is False

    def test_unknown_5xx_retryable(self) -> None:
        err = VigilError("Unknown", status_code=599)
        assert _should_retry(err) is True

    def test_unknown_4xx_not_retryable(self) -> None:
        err = VigilError("Unknown", status_code=418)
        assert _should_retry(err) is False
