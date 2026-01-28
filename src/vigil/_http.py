"""
Vigil Guard SDK HTTP Transport.

Provides synchronous HTTP transport with connection pooling,
TLS/mTLS support, proxy configuration, and idempotency keys.
"""

from __future__ import annotations

import inspect
import uuid
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urlsplit, urlunsplit

import httpx

from ._config import ClientConfig
from ._errors import (
    VigilConnectionError,
    VigilTimeoutError,
    _raise_for_status,
)
from ._retry import parse_retry_after
from ._version import __version__

DEFAULT_USER_AGENT = f"vigil-python/{__version__}"


class HttpTransport:
    """
    Synchronous HTTP transport for Vigil Guard API.

    Features:
    - Connection pooling with configurable limits
    - TLS/mTLS support
    - Proxy configuration
    - Automatic idempotency key generation for POST
    - Request ID extraction from responses
    """

    def __init__(self, config: ClientConfig) -> None:
        self._config = config
        self._client: Optional[httpx.Client] = None

    def _get_client(self) -> httpx.Client:
        """Lazy initialization of HTTP client with connection pooling."""
        if self._client is None:
            self._client = self._create_client()
        return self._client

    def _create_client(self) -> httpx.Client:
        """Create configured httpx client."""
        timeout = httpx.Timeout(
            timeout=self._config.timeout,
            connect=self._config.connect_timeout,
            read=self._config.read_timeout,
            write=self._config.write_timeout,
            pool=self._config.pool_timeout,
        )

        limits = httpx.Limits(
            max_connections=self._config.max_connections,
            max_keepalive_connections=self._config.max_keepalive_connections,
            keepalive_expiry=self._config.keepalive_expiry,
        )

        cert: Optional[Union[Tuple[str, str], str]] = None
        if self._config.mtls_cert:
            cert = self._config.mtls_cert
        elif self._config.client_cert:
            if self._config.client_key:
                cert = (self._config.client_cert, self._config.client_key)
            else:
                cert = self._config.client_cert

        verify: Union[bool, str] = self._config.verify
        if self._config.ca_bundle:
            verify = self._config.ca_bundle

        return httpx.Client(
            base_url=self._config.base_url,
            timeout=timeout,
            limits=limits,
            verify=verify,
            cert=cert,
            headers=self._build_default_headers(),
            **self._build_proxy_kwargs(),
        )

    def _build_default_headers(self) -> Dict[str, str]:
        """Build default headers for all requests."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": DEFAULT_USER_AGENT,
            "Authorization": f"Bearer {self._config.api_key}",
        }
        headers.update(self._config.default_headers)
        return headers

    def _get_proxy(self) -> Optional[str]:
        """Return proxy URL with optional embedded credentials."""
        proxy = self._config.proxy
        if not proxy or not self._config.proxy_auth:
            return proxy

        parsed = urlsplit(proxy)
        if parsed.username or parsed.password or not parsed.scheme or not parsed.hostname:
            return proxy

        username, password = self._config.proxy_auth
        netloc = f"{parsed.hostname}:{parsed.port}" if parsed.port else parsed.hostname
        auth_netloc = f"{username}:{password}@{netloc}"
        return urlunsplit((parsed.scheme, auth_netloc, parsed.path, parsed.query, parsed.fragment))

    def _build_proxy_kwargs(self) -> Dict[str, Any]:
        """Build proxy kwargs compatible with httpx 0.25+ and 0.28+."""
        proxy = self._get_proxy()
        if not proxy:
            return {}
        try:
            params = inspect.signature(httpx.Client).parameters
            if "proxy" in params:
                return {"proxy": proxy}
            if "proxies" in params:
                return {"proxies": proxy}
        except (TypeError, ValueError):
            pass
        return {"proxy": proxy}

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute HTTP request with error handling.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: API path (e.g., /v1/guard/input)
            json: JSON body for POST/PUT requests
            headers: Additional headers for this request
            timeout: Override timeout for this request
            idempotency_key: Idempotency key for POST requests

        Returns:
            Parsed JSON response

        Raises:
            VigilConnectionError: Network connectivity issues
            VigilTimeoutError: Request timeout
            VigilAuthenticationError: 401/403 responses
            VigilRateLimitError: 429 responses
            VigilValidationError: 400/422 responses
            VigilServiceError: 5xx responses
            VigilAPIError: Other error responses
        """
        client = self._get_client()
        request_headers = dict(headers) if headers else {}

        if method.upper() == "POST" and idempotency_key:
            request_headers["X-Idempotency-Key"] = idempotency_key

        request_timeout: Optional[httpx.Timeout] = None
        if timeout is not None:
            request_timeout = httpx.Timeout(
                timeout=timeout,
                connect=self._config.connect_timeout,
                read=self._config.read_timeout,
                write=self._config.write_timeout,
                pool=self._config.pool_timeout,
            )

        try:
            request_kwargs: Dict[str, Any] = {
                "method": method,
                "url": path,
                "json": json,
                "headers": request_headers,
            }
            if request_timeout is not None:
                request_kwargs["timeout"] = request_timeout
            response = client.request(**request_kwargs)
        except httpx.ConnectError as e:
            raise VigilConnectionError(f"Failed to connect to {self._config.base_url}: {e}") from e
        except httpx.TimeoutException as e:
            timeout_value = timeout if timeout is not None else self._config.timeout
            raise VigilTimeoutError(
                f"Request timed out after {timeout_value}s",
                timeout=timeout_value,
            ) from e
        except httpx.HTTPError as e:
            raise VigilConnectionError(f"HTTP error: {e}") from e

        body = self._parse_response_body(response)
        request_id = self._extract_request_id(response, body)

        if response.status_code >= 400:
            self._apply_retry_after_header(response, body)
            _raise_for_status(response.status_code, body, request_id)

        return body

    def _extract_request_id(
        self, response: httpx.Response, body: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """Extract request ID from response headers or body."""
        request_id: Optional[str] = response.headers.get("X-Request-Id") or response.headers.get(
            "x-request-id"
        )
        if request_id:
            return request_id
        if body:
            return body.get("requestId")
        return None

    def _apply_retry_after_header(self, response: httpx.Response, body: Dict[str, Any]) -> None:
        """Inject Retry-After header data into error body when missing."""
        if "retryAfter" not in body:
            retry_after_header = response.headers.get("Retry-After")
            if retry_after_header:
                retry_after = parse_retry_after(retry_after_header)
                if retry_after is not None:
                    body["retryAfter"] = int(retry_after)

        if "limit" not in body:
            limit_header = response.headers.get("X-RateLimit-Limit")
            if limit_header and limit_header.isdigit():
                body["limit"] = int(limit_header)

        if "resetAt" not in body:
            reset_header = response.headers.get("X-RateLimit-Reset")
            if reset_header:
                body["resetAt"] = reset_header

    def _parse_response_body(self, response: httpx.Response) -> Dict[str, Any]:
        """Parse response body as JSON."""
        if not response.content:
            return {}
        try:
            result: Dict[str, Any] = response.json()
            return result
        except ValueError:
            return {"error": response.text}

    def close(self) -> None:
        """Close the HTTP client and release connections."""
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> HttpTransport:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def generate_idempotency_key() -> str:
    """Generate a unique idempotency key for POST requests."""
    return f"idem_{uuid.uuid4().hex}"
