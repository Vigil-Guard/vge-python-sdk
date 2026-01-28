"""
Vigil Guard SDK Configuration.

Provides ClientConfig dataclass for SDK initialization with enterprise options
including timeouts, proxy, TLS/mTLS, and connection pool configuration.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urlparse

from ._errors import VigilConfigurationError

# API key format regex (base64url-compatible suffix)
API_KEY_PATTERN = re.compile(r"^vg_(live|test)_[a-zA-Z0-9_-]{32,}$")
DEFAULT_BASE_URL = "https://api.vigilguard.ai"


def _get_env_float(name: str, default: float) -> float:
    """Get float from environment variable with fallback."""
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _get_env_int(name: str, default: int) -> int:
    """Get integer from environment variable with fallback."""
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_env_bool(name: str, default: bool) -> bool:
    """Get boolean from environment variable with fallback."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in ("true", "1", "yes")


def _resolve_base_url(base_url: Optional[str]) -> str:
    """
    Resolve base_url from parameter or environment.

    Falls back to the public API base URL when not provided.
    """
    url = base_url or os.environ.get("VIGIL_GUARD_BASE_URL") or DEFAULT_BASE_URL
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise VigilConfigurationError(
            "Invalid base_url. Expected a full URL like https://api.vigilguard.ai"
        )
    return url.rstrip("/")


def _resolve_api_key(api_key: Optional[str]) -> str:
    """
    Resolve api_key from parameter or environment.

    Raises:
        VigilConfigurationError: If api_key is not provided or has invalid format.
    """
    key = api_key or os.environ.get("VIGIL_GUARD_API_KEY")
    if not key:
        raise VigilConfigurationError(
            "api_key is required. Set VIGIL_GUARD_API_KEY environment variable "
            "or pass api_key parameter."
        )
    if not API_KEY_PATTERN.match(key):
        raise VigilConfigurationError(
            f"Invalid API key format. Expected pattern: vg_(live|test)_<32+ chars>. "
            f"Got: {key[:20]}..."
        )
    return key


def _validate_file_path(label: str, path: Optional[str]) -> None:
    """Validate that a file path exists on disk."""
    if not path:
        return
    if not os.path.isfile(path):
        raise VigilConfigurationError(f"{label} file not found: {path}")


@dataclass
class ClientConfig:
    """
    Configuration for Vigil Guard SDK client.

    Attributes:
        api_key: API key for authentication (required)
        base_url: Base URL of the API (defaults to public API base URL)
        timeout: Total request timeout in seconds
        connect_timeout: Connection timeout in seconds
        read_timeout: Read timeout in seconds
        write_timeout: Write timeout in seconds
        pool_timeout: Pool acquisition timeout in seconds
        max_retries: Maximum number of retry attempts
        max_connections: Maximum connections in pool
        max_keepalive_connections: Maximum keepalive connections
        keepalive_expiry: Keepalive connection expiry in seconds
        proxy: HTTP proxy URL
        proxy_auth: Proxy authentication (username, password)
        verify: Verify SSL certificates
        ca_bundle: Path to CA bundle file
        client_cert: Path to client certificate
        client_key: Path to client key
        mtls_cert: Tuple of (cert_path, key_path) for mTLS
        strict_mode: Raise on unknown fields in API responses
        default_headers: Default headers to include in all requests
    """

    # Required (resolved from params or env)
    api_key: str = field(default="")
    base_url: str = field(default="")

    # Timeouts
    timeout: float = field(default=30.0)
    connect_timeout: float = field(default=5.0)
    read_timeout: Optional[float] = field(default=None)
    write_timeout: Optional[float] = field(default=None)
    pool_timeout: Optional[float] = field(default=None)

    # Retry
    max_retries: int = field(default=3)

    # Connection pool
    max_connections: int = field(default=100)
    max_keepalive_connections: int = field(default=20)
    keepalive_expiry: float = field(default=5.0)

    # Proxy
    proxy: Optional[str] = field(default=None)
    proxy_auth: Optional[Tuple[str, str]] = field(default=None)

    # TLS
    verify: bool = field(default=True)
    ca_bundle: Optional[str] = field(default=None)
    client_cert: Optional[str] = field(default=None)
    client_key: Optional[str] = field(default=None)
    mtls_cert: Optional[Tuple[str, str]] = field(default=None)

    # Forward compatibility
    strict_mode: bool = field(default=False)

    # Custom headers
    default_headers: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_params(
        cls,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
        connect_timeout: Optional[float] = None,
        read_timeout: Optional[float] = None,
        write_timeout: Optional[float] = None,
        pool_timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        max_connections: Optional[int] = None,
        max_keepalive_connections: Optional[int] = None,
        keepalive_expiry: Optional[float] = None,
        proxy: Optional[str] = None,
        proxy_auth: Optional[Tuple[str, str]] = None,
        verify: Optional[bool] = None,
        ca_bundle: Optional[str] = None,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        mtls_cert: Optional[Tuple[str, str]] = None,
        strict_mode: Optional[bool] = None,
        default_headers: Optional[Dict[str, str]] = None,
    ) -> ClientConfig:
        """
        Create config from parameters with environment variable fallbacks.

        Environment Variables:
            VIGIL_GUARD_API_KEY: API key
            VIGIL_GUARD_BASE_URL: Base URL (default: https://api.vigilguard.ai)
            VIGIL_GUARD_TIMEOUT: Total timeout
            VIGIL_GUARD_CONNECT_TIMEOUT: Connection timeout
            VIGIL_GUARD_MAX_RETRIES: Maximum retries
            VIGIL_GUARD_MAX_CONNECTIONS: Max pool connections
            VIGIL_GUARD_PROXY: Proxy URL
            VIGIL_GUARD_VERIFY_SSL: Verify SSL (true/false)
            VIGIL_GUARD_CA_BUNDLE: CA bundle path
            VIGIL_GUARD_STRICT_MODE: Strict mode (true/false)
        """
        resolved_api_key = _resolve_api_key(api_key)
        resolved_base_url = _resolve_base_url(base_url)

        config = cls(
            api_key=resolved_api_key,
            base_url=resolved_base_url,
            timeout=timeout if timeout is not None else _get_env_float("VIGIL_GUARD_TIMEOUT", 30.0),
            connect_timeout=connect_timeout
            if connect_timeout is not None
            else _get_env_float("VIGIL_GUARD_CONNECT_TIMEOUT", 5.0),
            read_timeout=read_timeout,
            write_timeout=write_timeout,
            pool_timeout=pool_timeout,
            max_retries=max_retries
            if max_retries is not None
            else _get_env_int("VIGIL_GUARD_MAX_RETRIES", 3),
            max_connections=max_connections
            if max_connections is not None
            else _get_env_int("VIGIL_GUARD_MAX_CONNECTIONS", 100),
            max_keepalive_connections=max_keepalive_connections
            if max_keepalive_connections is not None
            else 20,
            keepalive_expiry=keepalive_expiry if keepalive_expiry is not None else 5.0,
            proxy=proxy or os.environ.get("VIGIL_GUARD_PROXY"),
            proxy_auth=proxy_auth,
            verify=verify if verify is not None else _get_env_bool("VIGIL_GUARD_VERIFY_SSL", True),
            ca_bundle=ca_bundle or os.environ.get("VIGIL_GUARD_CA_BUNDLE"),
            client_cert=client_cert,
            client_key=client_key,
            mtls_cert=mtls_cert,
            strict_mode=strict_mode
            if strict_mode is not None
            else _get_env_bool("VIGIL_GUARD_STRICT_MODE", False),
            default_headers=default_headers or {},
        )

        if config.mtls_cert:
            if config.client_cert or config.client_key:
                raise VigilConfigurationError(
                    "Use either mtls_cert or client_cert/client_key, not both."
                )
            try:
                cert_path, key_path = config.mtls_cert
            except (TypeError, ValueError) as exc:
                raise VigilConfigurationError(
                    "mtls_cert must be a (cert_path, key_path) tuple."
                ) from exc
            _validate_file_path("mTLS certificate", cert_path)
            _validate_file_path("mTLS key", key_path)
        else:
            if config.client_key and not config.client_cert:
                raise VigilConfigurationError(
                    "client_key provided without client_cert."
                )
            _validate_file_path("Client certificate", config.client_cert)
            _validate_file_path("Client key", config.client_key)

        _validate_file_path("CA bundle", config.ca_bundle)

        return config

    @property
    def is_test_mode(self) -> bool:
        """Check if using test API key."""
        return self.api_key.startswith("vg_test_")

    @property
    def is_live_mode(self) -> bool:
        """Check if using live API key."""
        return self.api_key.startswith("vg_live_")

    def get_timeout_config(self) -> Dict[str, Any]:
        """Get httpx timeout configuration."""
        return {
            "timeout": self.timeout,
            "connect": self.connect_timeout,
            "read": self.read_timeout,
            "write": self.write_timeout,
            "pool": self.pool_timeout,
        }

    def get_pool_limits(self) -> Dict[str, Union[int, float]]:
        """Get httpx pool limits configuration."""
        return {
            "max_connections": self.max_connections,
            "max_keepalive_connections": self.max_keepalive_connections,
            "keepalive_expiry": self.keepalive_expiry,
        }
