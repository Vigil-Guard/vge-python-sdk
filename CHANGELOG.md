# Changelog

All notable changes to the Vigil Guard Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2026-02-16

### Changed

- Version bump to align with Vigil Guard Enterprise 1.0.3 release

## [1.0.0] - 2026-01-14

### Added

- Initial release of the hand-crafted Python SDK
- Sync client (`Vigil`) with full API support
- Async client (`AsyncVigil`) with async context manager
- `detect(text)` - Analyze user input for prompt injection
- `detect_output(output)` - Analyze LLM output for data leakage
- `analyze(text, source)` - Analyze with explicit source type
- `batch(items)` - Process multiple texts in single request
- Comprehensive error hierarchy:
  - `VigilError` - Base exception
  - `VigilConfigurationError` - SDK configuration errors
  - `VigilAuthenticationError` - 401/403 errors
  - `VigilValidationError` - 400/422 errors with field details
  - `VigilRateLimitError` - 429 with retry_after
  - `VigilServiceError` - 5xx errors
  - `VigilConnectionError` - Network failures
  - `VigilTimeoutError` - Request timeouts
  - `VigilBatchPartialFailure` - Partial batch failures
- Response models with convenience properties:
  - `DetectionResult` with `is_safe`, `is_blocked`, `is_sanitized`
  - `BatchResult` with iteration support
- Detection branch models:
  - `HeuristicsBranch` with explanations and threat level
  - `SemanticBranch` with attack/safe similarity
  - `PIIBranch` with categories and entity count
  - `LLMGuardBranch` with verdict and model metadata
- Enterprise features:
  - HTTP proxy support
  - mTLS client certificates
  - Custom CA bundles
  - Connection pooling
  - Configurable timeouts
- Automatic retry with exponential backoff and jitter
- Idempotency key support for POST requests
- `with_options()` for per-request configuration
- Test/Live mode detection via API key prefix
- Forward-compatible response parsing (`extra="ignore"`)
- Full type hints (PEP 561 compliant with py.typed)

### Dependencies

- Python 3.9+
- httpx >= 0.25.0
- pydantic >= 2.0.0
