"""Error types raised by the Vigil Guard SDK."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class VigilError(Exception):
    """
    Base class for SDK errors.

    Attributes:
        message: Human-readable error description
        status_code: HTTP status code (if applicable)
        request_id: Request ID for support
        body: Raw API response body (if available)
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        request_id: Optional[str] = None,
        body: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.request_id = request_id
        self.body = body

    def __str__(self) -> str:
        parts = [self.message]
        if self.request_id:
            parts.append(f"(request_id={self.request_id})")
        return " ".join(parts)

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"status_code={self.status_code}, "
            f"request_id={self.request_id!r}"
            f")"
        )


class VigilConfigurationError(VigilError):
    """Invalid SDK configuration."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class VigilAuthenticationError(VigilError):
    """Authentication failed (401/403)."""

    def __init__(
        self,
        message: str = "Invalid or missing API key",
        *,
        status_code: int = 401,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, status_code=status_code, **kwargs)


class VigilLicenseError(VigilError):
    """Base class for license-related errors (403 with LICENSE_* codes)."""

    def __init__(
        self,
        message: str = "License error",
        *,
        error_code: Optional[str] = None,
        status_code: int = 403,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, status_code=status_code, **kwargs)
        self.error_code = error_code

    def __str__(self) -> str:
        base = super().__str__()
        if self.error_code:
            return f"{base} (code={self.error_code})"
        return base


class VigilLicenseExpiredError(VigilLicenseError):
    """License has expired (past grace period)."""

    def __init__(
        self,
        message: str = "Your license has expired",
        **kwargs: Any,
    ) -> None:
        super().__init__(message, error_code="LICENSE_EXPIRED", **kwargs)


class VigilLicenseRequiredError(VigilLicenseError):
    """No valid license (UNLICENSED or REVOKED)."""

    def __init__(
        self,
        message: str = "A valid license is required",
        **kwargs: Any,
    ) -> None:
        super().__init__(message, error_code="LICENSE_REQUIRED", **kwargs)


class VigilRateLimitError(VigilError):
    """Rate limit exceeded; inspect retry_after, limit, reset_at."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        *,
        retry_after: int = 60,
        limit: Optional[int] = None,
        reset_at: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, status_code=429, **kwargs)
        self.retry_after = retry_after
        self.limit = limit
        self.reset_at = reset_at

    def __str__(self) -> str:
        base = super().__str__()
        return f"{base} (retry_after={self.retry_after}s)"


class VigilValidationError(VigilError):
    """Request validation failed; inspect errors."""

    def __init__(
        self,
        message: str = "Validation failed",
        *,
        errors: Optional[List[Dict[str, Any]]] = None,
        status_code: int = 400,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, status_code=status_code, **kwargs)
        self.errors: List[Dict[str, Any]] = errors or []

    def __str__(self) -> str:
        base = super().__str__()
        if self.errors:
            details = "; ".join(
                f"{e.get('path', '?')}: {e.get('message', '?')}" for e in self.errors
            )
            return f"{base}: {details}"
        return base


class VigilAPIError(VigilError):
    """Other 4xx errors not mapped to a specific type."""

    def __init__(
        self,
        message: str = "API error",
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)


class VigilServiceError(VigilError):
    """Service errors (5xx)."""

    def __init__(
        self,
        message: str = "Service temporarily unavailable",
        *,
        retry_after: Optional[int] = None,
        status_code: int = 503,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, status_code=status_code, **kwargs)
        self.retry_after = retry_after


class VigilConnectionError(VigilError):
    """Network failures (named to avoid builtins.ConnectionError)."""

    def __init__(
        self,
        message: str = "Failed to connect to Vigil Guard API",
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)


class VigilTimeoutError(VigilError):
    """Request timed out; inspect timeout."""

    def __init__(
        self,
        message: str = "Request timed out",
        *,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.timeout = timeout

    def __str__(self) -> str:
        base = super().__str__()
        if self.timeout:
            return f"{base} (timeout={self.timeout}s)"
        return base


class VigilRetryBudgetExceeded(VigilError):
    """Retry budget exceeded before a successful response."""

    def __init__(
        self,
        *,
        retry_budget: float,
        elapsed: float,
        next_delay: float,
    ) -> None:
        message = (
            f"Retry budget exceeded after {elapsed:.2f}s "
            f"(budget={retry_budget:.2f}s, next_delay={next_delay:.2f}s)"
        )
        super().__init__(message)
        self.retry_budget = retry_budget
        self.elapsed = elapsed
        self.next_delay = next_delay


class VigilBatchPartialFailure(VigilError):
    """Partial batch failure with successful and failed items."""

    def __init__(
        self,
        message: str = "Batch request partially failed",
        *,
        successful: Optional[List[Dict[str, Any]]] = None,
        failed: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.successful: List[Dict[str, Any]] = successful or []
        self.failed: List[Dict[str, Any]] = failed or []

    def __str__(self) -> str:
        base = super().__str__()
        return f"{base} ({len(self.successful)} succeeded, {len(self.failed)} failed)"


def _raise_for_status(
    status_code: int,
    body: Dict[str, Any],
    request_id: Optional[str] = None,
) -> None:
    """Map HTTP status codes to SDK exceptions."""
    common: Dict[str, Any] = {"request_id": request_id, "body": body}
    message = body.get("error", f"Request failed with status {status_code}")

    if status_code == 400:
        raise VigilValidationError(
            message,
            errors=body.get("details", []),
            **common,
        )

    if status_code == 401:
        raise VigilAuthenticationError(message, **common)

    if status_code == 403:
        error_code = body.get("error")
        if error_code == "LICENSE_EXPIRED":
            raise VigilLicenseExpiredError(body.get("message", message), **common)
        if error_code == "LICENSE_REQUIRED":
            raise VigilLicenseRequiredError(body.get("message", message), **common)
        raise VigilAuthenticationError(
            message or "Access forbidden",
            status_code=403,
            **common,
        )

    if status_code == 404:
        raise VigilAPIError(
            message or "Not found",
            status_code=404,
            **common,
        )

    if status_code == 422:
        raise VigilValidationError(
            message,
            errors=body.get("details", []),
            status_code=422,
            **common,
        )

    if status_code == 429:
        raise VigilRateLimitError(
            message,
            retry_after=body.get("retryAfter", 60),
            limit=body.get("limit"),
            reset_at=body.get("resetAt"),
            **common,
        )

    if status_code >= 500:
        raise VigilServiceError(
            message,
            retry_after=body.get("retryAfter"),
            status_code=status_code,
            **common,
        )

    # Fallback for other 4xx errors
    raise VigilAPIError(
        message,
        status_code=status_code,
        **common,
    )


def _should_retry(error: VigilError) -> bool:
    """Determine if error should trigger retry."""
    # Network errors - always retry
    if isinstance(error, (VigilConnectionError, VigilTimeoutError)):
        return True

    # Rate limit - always retry (with delay)
    if isinstance(error, VigilRateLimitError):
        return True

    # Server errors - retry
    if isinstance(error, VigilServiceError):
        return True

    # License errors - don't retry
    if isinstance(error, VigilLicenseError):
        return False

    # Client errors - don't retry
    if isinstance(error, (VigilAuthenticationError, VigilValidationError, VigilAPIError)):
        return False

    # Configuration errors - don't retry
    if isinstance(error, VigilConfigurationError):
        return False

    if isinstance(error, VigilRetryBudgetExceeded):
        return False

    # Unknown errors with 5xx status - retry
    return error.status_code is not None and error.status_code >= 500
