"""
Vigil Guard SDK Test Configuration.

Provides fixtures for testing without real network connections.
Global network blocking ensures no accidental HTTP requests.
"""

from __future__ import annotations

import sys
from collections.abc import Generator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import respx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

if TYPE_CHECKING:
    from vigil import Vigil

DUMMY_BASE_URL = "https://api.vigilguard.test.local"
DUMMY_API_KEY = "vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


@pytest.fixture(autouse=True)
def block_network() -> Generator[respx.MockRouter, None, None]:
    """
    Global network block - prevents any real HTTP requests.

    assert_all_mocked=True: Any unmocked request raises an error
    assert_all_called=False: Don't require all mocked routes to be called

    Tests add explicit routes: respx_mock.post(...).respond(...)
    """
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as mock:
        yield mock


@pytest.fixture
def mock_base_url() -> str:
    """Dummy base_url for testing - never makes real connections."""
    return DUMMY_BASE_URL


@pytest.fixture
def mock_api_key() -> str:
    """Dummy API key for testing."""
    return DUMMY_API_KEY


@pytest.fixture
def mock_client(mock_base_url: str, mock_api_key: str) -> Vigil:
    """Create client with dummy config for testing."""
    from vigil import Vigil

    return Vigil(api_key=mock_api_key, base_url=mock_base_url)


@pytest.fixture
def respx_mock(block_network: respx.MockRouter) -> respx.MockRouter:
    """
    Pre-configured respx mock for adding specific route mocks.

    Usage in tests:
        def test_detect(respx_mock, mock_client):
            respx_mock.post(f"{DUMMY_BASE_URL}/v1/guard/input").respond(
                json={"decision": "ALLOWED", ...}
            )
            result = mock_client.detect("test")
    """
    return block_network


@pytest.fixture
def mock_detect_response() -> dict[str, object]:
    """Standard detect response for contract tests."""
    return {
        "requestId": "req_123",
        "decision": "ALLOWED",
        "score": 15,
        "threatLevel": "LOW",
        "confidence": 0.95,
        "categories": [],
        "branches": {
            "heuristics": {"score": 10, "threatLevel": "LOW", "explanations": []},
            "semantic": {"score": 5, "attackSimilarity": 0.1, "safeSimilarity": 0.9},
            "pii": {"detected": False, "entityCount": 0, "categories": []},
        },
        "latencyMs": 12,
        "timestamp": "2024-01-15T10:30:00Z",
    }


@pytest.fixture
def mock_error_response() -> dict[str, object]:
    """Standard error response for contract tests."""
    return {
        "error": "Validation failed",
        "details": [{"path": "prompt", "message": "Prompt is required"}],
    }
