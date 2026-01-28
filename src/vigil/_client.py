"""Synchronous client for the Vigil Guard API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel

from ._config import ClientConfig
from ._errors import VigilAPIError
from ._http import HttpTransport, generate_idempotency_key
from ._retry import RetryConfig
from .types._validation import validate_no_extra_fields
from .types.enums import Source
from .types.requests import (
    BatchItem,
    BatchPayload,
    GuardAnalyzePayload,
    GuardInputPayload,
    GuardOutputPayload,
)
from .types.responses import BatchResult, DetectionResult


class Vigil:
    """Sync client for the Vigil Guard API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        *,
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
    ) -> None:
        """Create a client.

        api_key and base_url fall back to env vars. Other parameters override defaults.
        """
        self._config = ClientConfig.from_params(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            write_timeout=write_timeout,
            pool_timeout=pool_timeout,
            max_retries=max_retries,
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
            keepalive_expiry=keepalive_expiry,
            proxy=proxy,
            proxy_auth=proxy_auth,
            verify=verify,
            ca_bundle=ca_bundle,
            client_cert=client_cert,
            client_key=client_key,
            mtls_cert=mtls_cert,
            strict_mode=strict_mode,
            default_headers=default_headers,
        )
        self._transport = HttpTransport(self._config)
        self._retry = RetryConfig(max_retries=self._config.max_retries).create_handler()

    def detect(
        self,
        text: str,
        *,
        metadata: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> DetectionResult:
        """Analyze user input for prompt injection."""
        payload = GuardInputPayload(prompt=text, metadata=metadata or {})
        key = idempotency_key or generate_idempotency_key()

        response = self._retry.execute(
            self._transport,
            "POST",
            "/v1/guard/input",
            json=payload.to_dict(),
            timeout=timeout,
            idempotency_key=key,
        )

        self._validate_response(DetectionResult, response)
        return DetectionResult.model_validate(response)

    def detect_output(
        self,
        output: str,
        *,
        original_prompt: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> DetectionResult:
        """Analyze model output for leakage or injection."""
        payload = GuardOutputPayload(
            output=output,
            original_prompt=original_prompt,
            metadata=metadata or {},
        )
        key = idempotency_key or generate_idempotency_key()

        response = self._retry.execute(
            self._transport,
            "POST",
            "/v1/guard/output",
            json=payload.to_dict(),
            timeout=timeout,
            idempotency_key=key,
        )

        self._validate_response(DetectionResult, response)
        return DetectionResult.model_validate(response)

    def analyze(
        self,
        text: str,
        source: Source,
        *,
        metadata: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> DetectionResult:
        """Analyze text with an explicit Source value."""
        payload = GuardAnalyzePayload(text=text, source=source, metadata=metadata or {})
        key = idempotency_key or generate_idempotency_key()

        response = self._retry.execute(
            self._transport,
            "POST",
            "/v1/guard/analyze",
            json=payload.to_dict(),
            timeout=timeout,
            idempotency_key=key,
        )

        self._validate_response(DetectionResult, response)
        return DetectionResult.model_validate(response)

    def batch(
        self,
        items: List[BatchItem],
        *,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> BatchResult:
        """Analyze multiple items in a single request."""
        payload = BatchPayload(items=items)
        key = idempotency_key or generate_idempotency_key()

        response = self._retry.execute(
            self._transport,
            "POST",
            "/v1/guard/batch",
            json=payload.to_dict(),
            timeout=timeout,
            idempotency_key=key,
        )

        self._validate_response(BatchResult, response)
        return BatchResult.model_validate(response)

    def with_options(
        self,
        *,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
    ) -> Vigil:
        """Return a client copy with updated timeout/retry settings.

        Note:
            This creates a new client with its own connection pool. Reuse the
            returned client when applying the same override repeatedly.
        """
        new_timeout = timeout if timeout is not None else self._config.timeout
        new_retries = max_retries if max_retries is not None else self._config.max_retries

        return Vigil(
            api_key=self._config.api_key,
            base_url=self._config.base_url,
            timeout=new_timeout,
            connect_timeout=self._config.connect_timeout,
            read_timeout=self._config.read_timeout,
            write_timeout=self._config.write_timeout,
            pool_timeout=self._config.pool_timeout,
            max_retries=new_retries,
            max_connections=self._config.max_connections,
            max_keepalive_connections=self._config.max_keepalive_connections,
            keepalive_expiry=self._config.keepalive_expiry,
            proxy=self._config.proxy,
            proxy_auth=self._config.proxy_auth,
            verify=self._config.verify,
            ca_bundle=self._config.ca_bundle,
            client_cert=self._config.client_cert,
            client_key=self._config.client_key,
            mtls_cert=self._config.mtls_cert,
            strict_mode=self._config.strict_mode,
            default_headers=self._config.default_headers,
        )

    def _validate_response(self, model: type[BaseModel], response: Dict[str, Any]) -> None:
        if not self._config.strict_mode:
            return
        try:
            validate_no_extra_fields(model, response)
        except ValueError as exc:
            request_id = response.get("requestId")
            raise VigilAPIError(str(exc), request_id=request_id, body=response) from exc

    @property
    def is_test_mode(self) -> bool:
        """Check if using test API key."""
        return self._config.is_test_mode

    @property
    def is_live_mode(self) -> bool:
        """Check if using live API key."""
        return self._config.is_live_mode

    def close(self) -> None:
        """Close the client and release resources."""
        self._transport.close()

    def __enter__(self) -> Vigil:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __repr__(self) -> str:
        mode = "test" if self.is_test_mode else "live"
        return f"Vigil(base_url={self._config.base_url!r}, mode={mode})"
