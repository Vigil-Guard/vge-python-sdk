"""
Vigil Guard SDK Retry Handler.

Provides retry logic with exponential backoff, jitter,
and Retry-After header support.
"""

from __future__ import annotations

import random
import time
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, Any, Dict, Optional, TypeVar

from ._errors import (
    VigilError,
    VigilRateLimitError,
    VigilRetryBudgetExceeded,
    VigilServiceError,
    _should_retry,
)

if TYPE_CHECKING:
    from ._http import HttpTransport

T = TypeVar("T")

DEFAULT_BASE_DELAY = 0.5
DEFAULT_MAX_DELAY = 60.0
DEFAULT_JITTER_FACTOR = 0.25
DEFAULT_RETRY_BUDGET = 120.0

JITTER_RNG = random.SystemRandom()


class RetryHandler:
    """
    Retry handler with exponential backoff and jitter.

    Features:
    - Exponential backoff: base_delay * 2^attempt
    - Random jitter to prevent thundering herd
    - Respects Retry-After header from 429/503 responses
    - Configurable retry budget (max total retry time)
    - Preserves idempotency key across retries
    """

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = DEFAULT_BASE_DELAY,
        max_delay: float = DEFAULT_MAX_DELAY,
        jitter_factor: float = DEFAULT_JITTER_FACTOR,
        retry_budget: float = DEFAULT_RETRY_BUDGET,
    ) -> None:
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter_factor = jitter_factor
        self.retry_budget = retry_budget

    def execute(
        self,
        transport: HttpTransport,
        method: str,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute request with retry logic.

        Args:
            transport: HTTP transport to use
            method: HTTP method
            path: API path
            json: Request body
            headers: Additional headers
            timeout: Request timeout
            idempotency_key: Idempotency key (preserved across retries)

        Returns:
            Parsed JSON response

        Raises:
            VigilError: After all retries exhausted
        """
        last_error: Optional[VigilError] = None
        total_time = 0.0

        for attempt in range(self.max_retries + 1):
            try:
                return transport.request(
                    method=method,
                    path=path,
                    json=json,
                    headers=headers,
                    timeout=timeout,
                    idempotency_key=idempotency_key,
                )
            except VigilError as e:
                last_error = e

                if not _should_retry(e):
                    raise

                if attempt >= self.max_retries:
                    raise

                delay = self._calculate_delay(attempt, e)

                if total_time + delay > self.retry_budget:
                    raise VigilRetryBudgetExceeded(
                        retry_budget=self.retry_budget,
                        elapsed=total_time,
                        next_delay=delay,
                    ) from e

                time.sleep(delay)
                total_time += delay

        if last_error is not None:
            raise last_error
        raise RuntimeError("Unexpected state in retry loop")

    def _calculate_delay(self, attempt: int, error: VigilError) -> float:
        """
        Calculate delay before next retry.

        Honors Retry-After header if present, otherwise uses
        exponential backoff with jitter.
        """
        retry_after = self._get_retry_after(error)
        if retry_after is not None:
            return min(retry_after, self.max_delay)

        base = min(self.base_delay * (2**attempt), self.max_delay)
        jitter = base * self.jitter_factor * JITTER_RNG.random()
        result: float = base + jitter
        return result

    def _get_retry_after(self, error: VigilError) -> Optional[float]:
        """Extract Retry-After value from error if available."""
        if isinstance(error, VigilRateLimitError):
            return float(error.retry_after)

        if isinstance(error, VigilServiceError) and error.retry_after is not None:
            return float(error.retry_after)

        return None


def parse_retry_after(value: Optional[str]) -> Optional[float]:
    """
    Parse Retry-After header value.

    Supports both integer seconds and HTTP-date format.

    Args:
        value: Retry-After header value

    Returns:
        Seconds to wait, or None if parsing fails
    """
    if not value:
        return None

    try:
        return float(value)
    except ValueError:
        pass

    try:
        dt = parsedate_to_datetime(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delay = dt.timestamp() - time.time()
        return max(0.0, delay)
    except (ValueError, TypeError):
        return None


class RetryConfig:
    """Configuration for retry behavior."""

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = DEFAULT_BASE_DELAY,
        max_delay: float = DEFAULT_MAX_DELAY,
        jitter_factor: float = DEFAULT_JITTER_FACTOR,
        retry_budget: float = DEFAULT_RETRY_BUDGET,
    ) -> None:
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter_factor = jitter_factor
        self.retry_budget = retry_budget

    def create_handler(self) -> RetryHandler:
        """Create RetryHandler from this configuration."""
        return RetryHandler(
            max_retries=self.max_retries,
            base_delay=self.base_delay,
            max_delay=self.max_delay,
            jitter_factor=self.jitter_factor,
            retry_budget=self.retry_budget,
        )
