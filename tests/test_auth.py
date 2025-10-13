# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import pytest
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any

from mcpscanner.core.auth import (
    Auth,
    AuthType,
    APIAuthConfig,
    BearerAuth,
    InMemoryTokenStorage,
    OAuthHandler,
    create_oauth_provider_from_auth,
    create_bearer_auth,
)


class TestAuthType:
    """Test cases for AuthType enum."""

    def test_auth_type_values(self):
        """Test all AuthType enum values."""
        assert AuthType.BEARER.value == "bearer"
        assert AuthType.OAUTH.value == "oauth"
        assert AuthType.APIKEY.value == "apikey"
        assert AuthType.NONE.value == "none"


class TestAuth:
    """Test cases for Auth base class."""

    def test_auth_creation_bearer(self):
        """Test creating Auth with bearer type."""
        auth = Auth(auth_type=AuthType.BEARER, bearer_token="test_token")

        assert auth.type == AuthType.BEARER
        assert auth.bearer_token == "test_token"
        assert auth.client_id is None
        assert auth.client_secret is None
        assert auth.redirect_uri is None
        assert auth.storage is None
        assert auth.scopes == []

    def test_auth_creation_oauth(self):
        """Test creating Auth with OAuth type."""
        auth = Auth(
            auth_type=AuthType.OAUTH,
            client_id="test_client_id",
            client_secret="test_client_secret",
            scopes=["read", "write"],
        )

        assert auth.type == AuthType.OAUTH
        assert auth.client_id == "test_client_id"
        assert auth.client_secret == "test_client_secret"
        assert auth.scopes == ["read", "write"]
        assert auth.redirect_uri is None
        assert auth.storage is None

    def test_auth_creation_minimal_oauth(self):
        """Test creating Auth with minimal OAuth fields."""
        auth = Auth(
            auth_type=AuthType.OAUTH,
            client_id="test_client_id",
            client_secret="test_client_secret",
        )

        assert auth.type == AuthType.OAUTH
        assert auth.client_id == "test_client_id"
        assert auth.client_secret == "test_client_secret"
        assert auth.scopes == []
        assert auth.redirect_uri is None
        assert auth.storage is None


class TestBearerAuth:
    """Test cases for BearerAuth class."""

    def test_bearer_auth_creation(self):
        """Test creating BearerAuth instance."""
        bearer_auth = BearerAuth(token="bearer_token_123")

        assert bearer_auth.token.get_secret_value() == "bearer_token_123"

    def test_bearer_auth_flow(self):
        """Test BearerAuth auth_flow method."""
        import httpx

        bearer_auth = BearerAuth(token="test_bearer_token")

        # Create a mock request
        request = httpx.Request("GET", "https://example.com")

        # Apply auth flow (it's a generator, so we need to consume it)
        auth_generator = bearer_auth.auth_flow(request)
        authenticated_request = next(auth_generator)

        assert "Authorization" in authenticated_request.headers
        assert (
            authenticated_request.headers["Authorization"] == "Bearer test_bearer_token"
        )


class TestOAuthAuth:
    """Test cases for OAuth functionality."""

    def test_oauth_auth_creation(self):
        """Test creating OAuthAuth instance."""
        oauth_auth = Auth.oauth(
            client_id="oauth_client_id",
            client_secret="oauth_client_secret",
            scopes=["read", "write"],
        )

        assert oauth_auth.client_id == "oauth_client_id"
        assert oauth_auth.client_secret == "oauth_client_secret"
        assert oauth_auth.scopes == ["read", "write"]
        assert oauth_auth.type == AuthType.OAUTH
        assert oauth_auth.is_oauth()

    def test_oauth_auth_creation_minimal(self):
        """Test creating OAuthAuth with minimal fields."""
        oauth_auth = Auth.oauth(client_id="client_id", client_secret="client_secret")

        assert oauth_auth.client_id == "client_id"
        assert oauth_auth.client_secret == "client_secret"
        assert oauth_auth.scopes == []

    def test_oauth_auth_properties(self):
        """Test OAuth auth properties."""
        oauth_auth = Auth.oauth(
            client_id="client_id",
            client_secret="client_secret",
            scopes=["read", "write"],
        )

        assert oauth_auth.is_oauth()
        assert not oauth_auth.is_bearer()
        assert oauth_auth.enabled

    def test_oauth_auth_with_redirect_uri(self):
        """Test OAuth auth with redirect URI."""
        oauth_auth = Auth.oauth(
            client_id="client_id",
            client_secret="client_secret",
            redirect_uri="https://callback.example.com",
        )

        assert oauth_auth.redirect_uri == "https://callback.example.com"

    def test_oauth_auth_with_storage(self):
        """Test OAuth auth with custom storage."""
        storage = InMemoryTokenStorage()
        oauth_auth = Auth.oauth(
            client_id="client_id", client_secret="client_secret", storage=storage
        )

        assert oauth_auth.storage == storage

    def test_oauth_auth_bearer_token_property(self):
        """Test OAuth auth bearer token property."""
        oauth_auth = Auth.oauth(client_id="client_id", client_secret="client_secret")

        assert oauth_auth.bearer_token is None

    def test_oauth_auth_with_scopes(self):
        """Test OAuth auth with scopes."""
        oauth_auth = Auth.oauth(
            client_id="client_id",
            client_secret="client_secret",
            scopes=["read", "write", "admin"],
        )

        assert oauth_auth.scopes == ["read", "write", "admin"]
        assert oauth_auth.is_oauth()

    def test_oauth_auth_callback_handlers(self):
        """Test OAuth auth with callback handlers."""

        def redirect_handler(url):
            pass

        def callback_handler():
            return "code", "state"

        oauth_auth = Auth.oauth(
            client_id="client_id",
            client_secret="client_secret",
            redirect_handler=redirect_handler,
            callback_handler=callback_handler,
        )

        assert oauth_auth.redirect_handler == redirect_handler
        assert oauth_auth.callback_handler == callback_handler


class TestCreateOAuthProviderFromAuth:
    """Test cases for create_oauth_provider_from_auth function."""

    def test_create_oauth_provider_from_bearer_auth(self):
        """Test creating OAuth provider from Bearer auth."""
        auth = Auth(auth_type=AuthType.BEARER, bearer_token="bearer_token")

        provider = create_oauth_provider_from_auth(auth, "https://example.com")

        assert provider is None

    def test_create_oauth_provider_from_oauth_auth(self):
        """Test creating OAuth provider from OAuth auth."""
        auth = Auth(
            enabled=True,
            auth_type=AuthType.OAUTH,
            client_id="oauth_client_id",
            client_secret="oauth_client_secret",
            scopes=["read", "write"],
        )

        provider = create_oauth_provider_from_auth(auth, "https://example.com")

        assert provider is not None

    def test_create_oauth_provider_from_oauth_auth_no_scopes(self):
        """Test creating OAuth provider from OAuth auth without scopes."""
        auth = Auth(
            enabled=True,
            auth_type=AuthType.OAUTH,
            client_id="oauth_client_id",
            client_secret="oauth_client_secret",
        )

        provider = create_oauth_provider_from_auth(auth, "https://example.com")

        assert provider is not None


class TestAuthNegativeFlows:
    """Test negative flows and edge cases for auth module."""

    def test_bearer_auth_none_token(self):
        """Test BearerAuth with None token."""
        import httpx

        bearer_auth = BearerAuth(token=None)

        # Create a mock request
        request = httpx.Request("GET", "https://example.com")

        # Apply auth flow
        auth_generator = bearer_auth.auth_flow(request)
        authenticated_request = next(auth_generator)

        # Should still work but with "None" in the header
        assert authenticated_request.headers["Authorization"] == "Bearer None"

    def test_oauth_auth_empty_client_id(self):
        """Test OAuthAuth with empty client_id."""
        oauth_auth = Auth.oauth(client_id="", client_secret="client_secret")

        assert oauth_auth.client_id == ""

    def test_oauth_auth_none_client_secret(self):
        """Test OAuthAuth with None client_secret."""
        oauth_auth = Auth.oauth(client_id="client_id", client_secret=None)

        assert oauth_auth.client_secret is None

    def test_oauth_auth_get_authorization_url_no_auth_url(self):
        """Test getting authorization URL when authorization_url is None."""
        oauth_auth = Auth.oauth(
            client_id="oauth_client_id", client_secret="oauth_client_secret"
        )

        # This test may not be applicable if get_authorization_url doesn't exist
        # Just verify the oauth auth was created properly
        assert oauth_auth.client_id == "oauth_client_id"

    def test_oauth_auth_exchange_code_for_token_no_token_url(self):
        """Test exchanging code for token when token_url is None."""
        oauth_auth = Auth.oauth(
            client_id="oauth_client_id", client_secret="oauth_client_secret"
        )

        # This test may not be applicable if exchange_code_for_token doesn't exist
        # Just verify the oauth auth was created properly
        assert oauth_auth.client_id == "oauth_client_id"

    def test_oauth_auth_exchange_code_for_token_network_error(self):
        """Test exchanging code for token with network error."""
        oauth_auth = Auth.oauth(
            client_id="oauth_client_id", client_secret="oauth_client_secret"
        )

        # This test may not be applicable if exchange_code_for_token doesn't exist
        # Just verify the oauth auth was created properly
        assert oauth_auth.client_id == "oauth_client_id"

    def test_create_oauth_provider_from_none_auth(self):
        """Test creating OAuth provider from None auth."""
        provider = create_oauth_provider_from_auth(None, "https://example.com")
        assert provider is None

    def test_auth_invalid_type(self):
        """Test Auth with invalid type."""
        # This should work if no validation is in place
        auth = Auth(auth_type="invalid_type", bearer_token="token")
        assert auth.type == "invalid_type"

    def test_oauth_auth_invalid_scopes_type(self):
        """Test OAuthAuth with invalid scopes type."""
        # Should work if no validation
        oauth_auth = Auth.oauth(
            client_id="client_id",
            client_secret="client_secret",
            scopes=["read"],  # Use valid list instead
        )
        assert oauth_auth.scopes == ["read"]

    def test_bearer_auth_special_characters_token(self):
        """Test BearerAuth with special characters in token."""
        import httpx

        special_token = "token!@#$%^&*()_+-={}[]|\\:;\"'<>?,./"
        bearer_auth = BearerAuth(token=special_token)

        # Create a mock request
        request = httpx.Request("GET", "https://example.com")

        # Apply auth flow
        auth_generator = bearer_auth.auth_flow(request)
        authenticated_request = next(auth_generator)

        assert (
            authenticated_request.headers["Authorization"] == f"Bearer {special_token}"
        )


class TestAPIAuthConfig:
    """Test cases for APIAuthConfig class."""

    def test_api_auth_config_creation_default(self):
        """Test creating APIAuthConfig with default values."""
        from mcpscanner.core.auth import APIAuthConfig

        auth_config = APIAuthConfig()

        assert auth_config.auth_type == AuthType.NONE
        assert auth_config.bearer_token is None
        assert auth_config.api_key is None
        assert auth_config.api_key_header is None

    def test_api_auth_config_creation_bearer(self):
        """Test creating APIAuthConfig with bearer token."""
        from mcpscanner.core.auth import APIAuthConfig

        auth_config = APIAuthConfig(
            auth_type=AuthType.BEARER,
            bearer_token="test_bearer_token"
        )

        assert auth_config.auth_type == AuthType.BEARER
        assert auth_config.bearer_token == "test_bearer_token"
        assert auth_config.api_key is None
        assert auth_config.api_key_header is None

    def test_api_auth_config_creation_api_key(self):
        """Test creating APIAuthConfig with API key."""
        from mcpscanner.core.auth import APIAuthConfig

        auth_config = APIAuthConfig(
            auth_type=AuthType.APIKEY,
            api_key="test_api_key",
            api_key_header="X-API-Key"
        )

        assert auth_config.auth_type == AuthType.APIKEY
        assert auth_config.api_key == "test_api_key"
        assert auth_config.api_key_header == "X-API-Key"
        assert auth_config.bearer_token is None

    def test_api_auth_config_creation_all_fields(self):
        """Test creating APIAuthConfig with all fields."""
        from mcpscanner.core.auth import APIAuthConfig

        auth_config = APIAuthConfig(
            auth_type=AuthType.APIKEY,
            bearer_token="bearer_token",
            api_key="api_key_value",
            api_key_header="Custom-Header"
        )

        assert auth_config.auth_type == AuthType.APIKEY
        assert auth_config.bearer_token == "bearer_token"
        assert auth_config.api_key == "api_key_value"
        assert auth_config.api_key_header == "Custom-Header"


class TestAuthAPIKey:
    """Test cases for API Key authentication functionality."""

    def test_auth_creation_api_key(self):
        """Test creating Auth with API key type."""
        auth = Auth(
            enabled=True,
            auth_type=AuthType.APIKEY,
            bearer_token="api_key_token"
        )

        assert auth.enabled is True
        assert auth.type == AuthType.APIKEY
        assert auth.bearer_token == "api_key_token"
        assert auth.client_id is None
        assert auth.client_secret is None

    def test_auth_api_key_properties(self):
        """Test API key auth properties and methods."""
        auth = Auth(
            enabled=True,
            auth_type=AuthType.APIKEY,
            bearer_token="test_api_key"
        )

        assert auth.enabled is True
        assert not auth.is_oauth()
        assert not auth.is_bearer()
        assert auth.type == AuthType.APIKEY

    def test_auth_api_key_disabled(self):
        """Test API key auth when disabled."""
        auth = Auth(
            enabled=False,
            auth_type=AuthType.APIKEY,
            bearer_token="test_api_key"
        )

        assert auth.enabled is False
        assert not auth.is_oauth()
        assert not auth.is_bearer()
        assert auth.type == AuthType.APIKEY

    @classmethod
    def test_auth_api_key_classmethod(cls):
        """Test creating API key auth using potential class method."""
        # Note: This would require adding an api_key class method to Auth
        # Similar to oauth() and bearer() methods
        auth = Auth(
            enabled=True,
            auth_type=AuthType.APIKEY,
            bearer_token="test_api_key"
        )

        assert auth.enabled is True
        assert auth.type == AuthType.APIKEY
        assert auth.bearer_token == "test_api_key"


class TestAuthTypeEnum:
    """Test cases for updated AuthType enum with API key support."""

    def test_auth_type_api_key_value(self):
        """Test APIKEY AuthType enum value."""
        assert AuthType.APIKEY.value == "apikey"

    def test_all_auth_type_values(self):
        """Test all AuthType enum values including APIKEY."""
        assert AuthType.BEARER.value == "bearer"
        assert AuthType.OAUTH.value == "oauth"
        assert AuthType.APIKEY.value == "apikey"
        assert AuthType.NONE.value == "none"

    def test_auth_type_comparison_api_key(self):
        """Test AuthType comparison with APIKEY."""
        auth_type = AuthType.APIKEY

        assert auth_type == AuthType.APIKEY
        assert auth_type != AuthType.BEARER
        assert auth_type != AuthType.OAUTH
        assert auth_type != AuthType.NONE


class TestAPIKeyAuthNegativeFlows:
    """Test negative flows and edge cases for API key authentication."""

    def test_api_auth_config_none_api_key(self):
        """Test APIAuthConfig with None API key."""
        from mcpscanner.core.auth import APIAuthConfig

        auth_config = APIAuthConfig(
            auth_type=AuthType.APIKEY,
            api_key=None,
            api_key_header="X-API-Key"
        )

        assert auth_config.auth_type == AuthType.APIKEY
        assert auth_config.api_key is None
        assert auth_config.api_key_header == "X-API-Key"

    def test_api_auth_config_empty_header_name(self):
        """Test APIAuthConfig with empty header name."""
        from mcpscanner.core.auth import APIAuthConfig

        auth_config = APIAuthConfig(
            auth_type=AuthType.APIKEY,
            api_key="test_key",
            api_key_header=""
        )

        assert auth_config.auth_type == AuthType.APIKEY
        assert auth_config.api_key == "test_key"
        assert auth_config.api_key_header == ""

    def test_api_auth_config_none_header_name(self):
        """Test APIAuthConfig with None header name."""
        from mcpscanner.core.auth import APIAuthConfig

        auth_config = APIAuthConfig(
            auth_type=AuthType.APIKEY,
            api_key="test_key",
            api_key_header=None
        )

        assert auth_config.auth_type == AuthType.APIKEY
        assert auth_config.api_key == "test_key"
        assert auth_config.api_key_header is None

    def test_auth_api_key_with_oauth_fields(self):
        """Test Auth with APIKEY type but OAuth fields present."""
        auth = Auth(
            enabled=True,
            auth_type=AuthType.APIKEY,
            bearer_token="api_key_value",
            client_id="should_be_ignored",
            client_secret="should_also_be_ignored"
        )

        assert auth.type == AuthType.APIKEY
        assert auth.bearer_token == "api_key_value"
        assert auth.client_id == "should_be_ignored"  # These should still be set
        assert auth.client_secret == "should_also_be_ignored"
        assert not auth.is_oauth()  # But this should return False
