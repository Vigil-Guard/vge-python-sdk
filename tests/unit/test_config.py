"""Unit tests for configuration."""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

from vigil import ClientConfig, VigilConfigurationError


@pytest.mark.unit
class TestClientConfig:
    """Tests for ClientConfig dataclass."""

    def test_default_values(self) -> None:
        config = ClientConfig(
            api_key="vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            base_url="https://api.vigilguard.test.local",
        )
        assert config.timeout == 30.0
        assert config.connect_timeout == 5.0
        assert config.max_retries == 3
        assert config.max_connections == 100
        assert config.verify is True
        assert config.strict_mode is False
        assert config.proxy is None
        assert config.mtls_cert is None

    def test_custom_values(self) -> None:
        config = ClientConfig(
            api_key="vg_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            base_url="https://api.vigilguard.customer.domain",
            timeout=60.0,
            connect_timeout=10.0,
            max_retries=5,
            proxy="http://proxy.corp.com:8080",
            verify=False,
            mtls_cert=("/path/to/client.crt", "/path/to/client.key"),
            strict_mode=True,
        )
        assert config.timeout == 60.0
        assert config.connect_timeout == 10.0
        assert config.max_retries == 5
        assert config.proxy == "http://proxy.corp.com:8080"
        assert config.verify is False
        assert config.mtls_cert == ("/path/to/client.crt", "/path/to/client.key")
        assert config.strict_mode is True

    def test_is_test_mode(self) -> None:
        config = ClientConfig(
            api_key="vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            base_url="https://api.vigilguard.test.local",
        )
        assert config.is_test_mode is True
        assert config.is_live_mode is False

    def test_is_live_mode(self) -> None:
        config = ClientConfig(
            api_key="vg_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            base_url="https://api.vigilguard.test.local",
        )
        assert config.is_live_mode is True
        assert config.is_test_mode is False

    def test_get_timeout_config(self) -> None:
        config = ClientConfig(
            api_key="vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            base_url="https://api.vigilguard.test.local",
            timeout=30.0,
            connect_timeout=5.0,
            read_timeout=10.0,
            write_timeout=15.0,
            pool_timeout=20.0,
        )
        timeout_config = config.get_timeout_config()
        assert timeout_config["timeout"] == 30.0
        assert timeout_config["connect"] == 5.0
        assert timeout_config["read"] == 10.0
        assert timeout_config["write"] == 15.0
        assert timeout_config["pool"] == 20.0

    def test_get_pool_limits(self) -> None:
        config = ClientConfig(
            api_key="vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            base_url="https://api.vigilguard.test.local",
            max_connections=200,
            max_keepalive_connections=50,
            keepalive_expiry=10.0,
        )
        pool_limits = config.get_pool_limits()
        assert pool_limits["max_connections"] == 200
        assert pool_limits["max_keepalive_connections"] == 50
        assert pool_limits["keepalive_expiry"] == 10.0


@pytest.mark.unit
class TestClientConfigFromParams:
    """Tests for ClientConfig.from_params factory method."""

    def test_from_params_with_explicit_values(self) -> None:
        config = ClientConfig.from_params(
            api_key="vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            base_url="https://api.vigilguard.test.local",
            timeout=45.0,
            max_retries=5,
        )
        assert config.api_key == "vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        assert config.base_url == "https://api.vigilguard.test.local"
        assert config.timeout == 45.0
        assert config.max_retries == 5

    def test_from_params_strips_trailing_slash(self) -> None:
        config = ClientConfig.from_params(
            api_key="vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            base_url="https://api.vigilguard.test.local/",
        )
        assert config.base_url == "https://api.vigilguard.test.local"

    def test_from_params_default_base_url(self) -> None:
        env = {
            "VIGIL_GUARD_API_KEY": "vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config = ClientConfig.from_params()
            assert config.base_url == "https://api.vigilguard.customer.domain"

    def test_from_params_missing_api_key_raises(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with pytest.raises(VigilConfigurationError) as exc_info:
                ClientConfig.from_params(
                    base_url="https://api.vigilguard.test.local"
                )
            assert "api_key is required" in str(exc_info.value)

    def test_from_params_invalid_api_key_format_raises(self) -> None:
        with pytest.raises(VigilConfigurationError) as exc_info:
            ClientConfig.from_params(
                api_key="invalid_key_format",
                base_url="https://api.vigilguard.test.local",
            )
        assert "Invalid API key format" in str(exc_info.value)

    def test_from_params_api_key_too_short_raises(self) -> None:
        with pytest.raises(VigilConfigurationError) as exc_info:
            ClientConfig.from_params(
                api_key="vg_test_short",
                base_url="https://api.vigilguard.test.local",
            )
        assert "Invalid API key format" in str(exc_info.value)

    def test_from_params_invalid_base_url_raises(self) -> None:
        with pytest.raises(VigilConfigurationError, match="Invalid base_url"):
            ClientConfig.from_params(
                api_key="vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                base_url="not a url",
            )

    def test_from_params_with_env_vars(self) -> None:
        env = {
            "VIGIL_GUARD_API_KEY": "vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "VIGIL_GUARD_BASE_URL": "https://api.vigilguard.env.local",
            "VIGIL_GUARD_TIMEOUT": "60.0",
            "VIGIL_GUARD_CONNECT_TIMEOUT": "10.0",
            "VIGIL_GUARD_MAX_RETRIES": "5",
            "VIGIL_GUARD_MAX_CONNECTIONS": "200",
            "VIGIL_GUARD_VERIFY_SSL": "false",
            "VIGIL_GUARD_STRICT_MODE": "true",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config = ClientConfig.from_params()
            assert config.api_key == "vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            assert config.base_url == "https://api.vigilguard.env.local"
            assert config.timeout == 60.0
            assert config.connect_timeout == 10.0
            assert config.max_retries == 5
            assert config.max_connections == 200
            assert config.verify is False
            assert config.strict_mode is True

    def test_from_params_explicit_overrides_env(self) -> None:
        env = {
            "VIGIL_GUARD_API_KEY": "vg_test_envkeyenvkeyenvkeyenvkeyenvkey",
            "VIGIL_GUARD_BASE_URL": "https://api.vigilguard.env.local",
            "VIGIL_GUARD_TIMEOUT": "60.0",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config = ClientConfig.from_params(
                api_key="vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                base_url="https://api.vigilguard.explicit.local",
                timeout=30.0,
            )
            assert config.api_key == "vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            assert config.base_url == "https://api.vigilguard.explicit.local"
            assert config.timeout == 30.0

    def test_from_params_invalid_env_timeout_uses_default(self) -> None:
        env = {
            "VIGIL_GUARD_API_KEY": "vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "VIGIL_GUARD_BASE_URL": "https://api.vigilguard.test.local",
            "VIGIL_GUARD_TIMEOUT": "not_a_number",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config = ClientConfig.from_params()
            assert config.timeout == 30.0

    def test_from_params_with_proxy(self) -> None:
        env = {
            "VIGIL_GUARD_API_KEY": "vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "VIGIL_GUARD_BASE_URL": "https://api.vigilguard.test.local",
            "VIGIL_GUARD_PROXY": "http://proxy.corp.com:8080",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config = ClientConfig.from_params()
            assert config.proxy == "http://proxy.corp.com:8080"

    def test_from_params_with_ca_bundle(self, tmp_path: Path) -> None:
        ca_bundle = tmp_path / "ca-bundle.crt"
        ca_bundle.write_text("test-ca")
        env = {
            "VIGIL_GUARD_API_KEY": "vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "VIGIL_GUARD_BASE_URL": "https://api.vigilguard.test.local",
            "VIGIL_GUARD_CA_BUNDLE": str(ca_bundle),
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config = ClientConfig.from_params()
            assert config.ca_bundle == str(ca_bundle)

    def test_client_key_without_cert_raises(self) -> None:
        with pytest.raises(VigilConfigurationError, match="client_key provided"):
            ClientConfig.from_params(
                api_key="vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                base_url="https://api.vigilguard.test.local",
                client_key="/missing/key.pem",
            )


@pytest.mark.unit
class TestApiKeyValidation:
    """Tests for API key format validation."""

    def test_valid_test_key(self) -> None:
        config = ClientConfig.from_params(
            api_key="vg_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            base_url="https://api.vigilguard.test.local",
        )
        assert config.is_test_mode is True

    def test_valid_live_key(self) -> None:
        config = ClientConfig.from_params(
            api_key="vg_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            base_url="https://api.vigilguard.test.local",
        )
        assert config.is_live_mode is True

    def test_valid_long_key(self) -> None:
        long_suffix = "a" * 64
        config = ClientConfig.from_params(
            api_key=f"vg_test_{long_suffix}",
            base_url="https://api.vigilguard.test.local",
        )
        assert config.api_key == f"vg_test_{long_suffix}"

    def test_valid_base64url_key(self) -> None:
        base64url_suffix = "abCD12_-abCD12_-abCD12_-abCD12_-"
        config = ClientConfig.from_params(
            api_key=f"vg_test_{base64url_suffix}",
            base_url="https://api.vigilguard.test.local",
        )
        assert config.api_key == f"vg_test_{base64url_suffix}"

    def test_invalid_prefix(self) -> None:
        with pytest.raises(VigilConfigurationError):
            ClientConfig.from_params(
                api_key="vg_invalid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                base_url="https://api.vigilguard.test.local",
            )

    def test_missing_prefix(self) -> None:
        with pytest.raises(VigilConfigurationError):
            ClientConfig.from_params(
                api_key="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                base_url="https://api.vigilguard.test.local",
            )

    def test_key_with_invalid_characters(self) -> None:
        with pytest.raises(VigilConfigurationError):
            ClientConfig.from_params(
                api_key="vg_test_aaaa!@#$aaaaaaaaaaaaaaaaaaaaaa",
                base_url="https://api.vigilguard.test.local",
            )
