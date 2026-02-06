"""
Vigil Guard Python SDK.

A hand-crafted Python SDK for Vigil Guard prompt injection detection API.

Quick Start:
    >>> from vigil import Vigil
    >>> client = Vigil(api_key="vg_live_...")
    >>> result = client.detect("user input text")
    >>> if result.is_safe:
    ...     print("Content is safe")

Async Usage:
    >>> from vigil import AsyncVigil
    >>> async with AsyncVigil(api_key="vg_live_...") as client:
    ...     result = await client.detect("user input text")

Enterprise Configuration:
    >>> client = Vigil(
    ...     api_key="vg_live_...",
    ...     base_url="https://api.vigilguard.customer.domain",
    ...     timeout=30.0,
    ...     proxy="http://proxy.corp.com:8080",
    ...     ca_bundle="/path/to/your/ca-bundle.crt",
    ...     client_cert="/path/to/client.crt",
    ...     client_key="/path/to/client.key",
    ... )
"""

from __future__ import annotations

from ._async_client import AsyncVigil
from ._client import Vigil
from ._config import ClientConfig
from ._errors import (
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
from ._version import __version__
from .types import Decision, Source, ThreatLevel
from .types.requests import BatchItem
from .types.responses import BatchResult, DetectionResult, LicenseStatus

__all__ = [
    # Version
    "__version__",
    # Clients
    "Vigil",
    "AsyncVigil",
    # Configuration
    "ClientConfig",
    # Errors
    "VigilError",
    "VigilConfigurationError",
    "VigilAuthenticationError",
    "VigilLicenseError",
    "VigilLicenseExpiredError",
    "VigilLicenseRequiredError",
    "VigilRateLimitError",
    "VigilValidationError",
    "VigilAPIError",
    "VigilServiceError",
    "VigilConnectionError",
    "VigilTimeoutError",
    "VigilRetryBudgetExceeded",
    "VigilBatchPartialFailure",
    # Types
    "Decision",
    "ThreatLevel",
    "Source",
    # Request/Response Models
    "BatchItem",
    "DetectionResult",
    "BatchResult",
    "LicenseStatus",
]
