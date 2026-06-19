# Changelog

All notable changes to the Vigil Guard Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.8.0] - 2026-06-19

### Added

- Typed `agent`, `tool`, and `conversation` request helpers for sync and async clients
- New `Source` values: `tool_input` and `system_prompt`
- Friendly compatibility error when typed requests target a pre-PRD_29 server
- Exported API contract constants: `MIN_TEXT_LENGTH`, `MAX_TEXT_LENGTH`,
  `MAX_BATCH_ITEMS`, and `MAX_METADATA_BYTES`
- Added `should_fail_closed(error)` helper for the Vigil Guard 1.8
  retry-then-block/hold contract on 503, timeout, transport, and retry-budget
  failures.

### Compatibility

- Typed `agent` / `tool` / `conversation` parameters require Vigil Guard server with PRD_29 Phase 1 deployed.
- Legacy `metadata=`-only calls remain compatible with earlier server versions.

### Changed

- Synced `/v1/guard/batch` with the Vigil Guard 1.8 contract: static SDK cap is
  24 items, metadata is capped at 16 KiB serialized, and text fields are
  validated as 1-100,000 characters before sending.
- `VigilValidationError` now exposes `max_safe_items` when a 1.8 server returns
  a deployment-specific batch budget error.

## [1.0.3] - 2026-02-16

### Fixed

- Pydantic `model_` namespace warning on `LlmGuardBranch` and `ContentModBranch`
- `get_license_status()` now routes through retry handler (sync and async)

### Added

- Unit tests for `validate_no_extra_fields()` strict-mode validation
- Async transport and retry handler tests (22 new tests)

### Changed

- Deduplicated `build_detection_response()` test helper into `conftest.py`
- Test coverage increased from 76% to 86%

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
