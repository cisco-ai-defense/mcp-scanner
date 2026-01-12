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

"""Authentication utilities for MCP Scanner SDK.

This module provides OAuth and Bearer token authentication support for MCP client connections,
including token storage and OAuth client provider setup.
"""

import asyncio
from enum import Enum
from typing import Optional, List, Callable, Tuple, Dict
from urllib.parse import parse_qs, urlparse

import httpx
from pydantic import AnyUrl, SecretStr, BaseModel
from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

from ..config.config import Config
from ..config.constants import CONSTANTS
from ..utils.logging_config import get_logger

logger = get_logger(__name__)


class AuthType(str, Enum):
    """Authentication type enumeration."""

    OAUTH = "oauth"
    BEARER = "bearer"
    APIKEY = "apikey"
    NONE = "none"

class APIAuthConfig(BaseModel):
    """Authentication configuration for MCP scanner requests."""

    auth_type: AuthType = AuthType.NONE
    bearer_token: Optional[str] = None
    api_key: Optional[str] = None
    api_key_header: Optional[str] = None
    custom_headers: Optional[Dict[str, str]] = None


class Auth:
    """Authentication configuration class for explicit auth control.

    This class allows users to explicitly specify authentication requirements
    and configuration for MCP server connections.

    Example:
        >>> auth = Auth(enabled=True, auth_type=AuthType.OAUTH,
        ...             client_id="client_id", client_secret="secret")
        >>> scanner.scan_remote_server_tools(server_url, auth=auth)
    """

    def __init__(
        self,
        enabled: bool = False,
        auth_type: AuthType = AuthType.NONE,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        redirect_uri: Optional[str] = None,
        storage: Optional[TokenStorage] = None,
        redirect_handler: Optional[Callable[[str], None]] = None,
        callback_handler: Optional[Callable[[], Tuple[str, Optional[str]]]] = None,
        bearer_token: Optional[str] = None,
        api_key : Optional[str] = None,
        api_key_header : Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
    ):
        """Initialize Auth configuration.

        Args:
            enabled (bool): Whether authentication is enabled.
            auth_type (AuthType): Type of authentication to use.
            client_id (Optional[str]): OAuth client ID.
            client_secret (Optional[str]): OAuth client secret.
            scopes (Optional[List[str]]): OAuth scopes.
            redirect_uri (Optional[str]): OAuth redirect URI.
            storage (Optional[TokenStorage]): Token storage implementation.
            redirect_handler (Optional[Callable]): Custom redirect handler.
            callback_handler (Optional[Callable]): Custom callback handler.
            bearer_token (Optional[str]): Bearer token for Bearer authentication.
            custom_headers (Optional[Dict[str, str]]): Custom HTTP headers to send with requests.
        """
        self.enabled = enabled
        self.type = auth_type
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes or []
        self.redirect_uri = redirect_uri
        self.storage = storage
        self.redirect_handler = redirect_handler
        self.callback_handler = callback_handler
        self.bearer_token = bearer_token
        self.api_key = api_key
        self.api_key_header = api_key_header
        self.custom_headers = custom_headers or {}

    def __bool__(self) -> bool:
        """Return True if authentication is enabled."""
        return self.enabled

    @classmethod
    def apikey(
        cls,
        api_key: str,
        api_key_header: str) -> "Auth":
        """Create API key authentication configuration.
        Args:
            api_key (str): The API key value.
            api_key_header (str): The HTTP header name for the API key (e.g., "X-API-Key").
        Returns:
            Auth: Configured API key authentication instance.
        """
        return cls(
            enabled=True,
            auth_type=AuthType.APIKEY,
            api_key=api_key,
            api_key_header=api_key_header
        )

    @classmethod
    def oauth(
        cls,
        client_id: str,
        client_secret: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        redirect_uri: Optional[str] = None,
        storage: Optional[TokenStorage] = None,
        redirect_handler: Optional[Callable[[str], None]] = None,
        callback_handler: Optional[Callable[[], Tuple[str, Optional[str]]]] = None,
    ) -> "Auth":
        """Create OAuth authentication configuration.

        Args:
            client_id (str): OAuth client ID.
            client_secret (Optional[str]): OAuth client secret.
            scopes (Optional[List[str]]): OAuth scopes.
            redirect_uri (Optional[str]): OAuth redirect URI.
            storage (Optional[TokenStorage]): Token storage implementation.
            redirect_handler (Optional[Callable]): Custom redirect handler.
            callback_handler (Optional[Callable]): Custom callback handler.

        Returns:
            Auth: Configured OAuth authentication instance.
        """
        return cls(
            enabled=True,
            auth_type=AuthType.OAUTH,
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
            redirect_uri=redirect_uri,
            storage=storage,
            redirect_handler=redirect_handler,
            callback_handler=callback_handler,
        )

    @classmethod
    def bearer(
        cls,
        bearer_token: str,
    ) -> "Auth":
        """Create Bearer authentication configuration.

        Args:
            bearer_token (str): Bearer token.

        Returns:
            Auth: Configured Bearer authentication instance.
        """
        return cls(
            enabled=True,
            auth_type=AuthType.BEARER,
            bearer_token=bearer_token,
        )

    def is_apikey(self) -> bool:
        """Check if this is API key authentication."""
        return self.enabled and self.type == AuthType.APIKEY
    def is_oauth(self) -> bool:
        """Check if this is OAuth authentication."""
        return self.enabled and self.type == AuthType.OAUTH

    def is_bearer(self) -> bool:
        """Check if this is Bearer authentication."""
        return self.enabled and self.type == AuthType.BEARER

    @classmethod
    def custom(cls, headers: Dict[str, str]) -> "Auth":
        """Create custom header authentication configuration.

        Args:
            headers (Dict[str, str]): Dictionary of custom headers to send.

        Returns:
            Auth: Configured custom header authentication instance.
        """
        return cls(
            enabled=True,
            auth_type=AuthType.NONE,
            custom_headers=headers,
        )


class InMemoryTokenStorage(TokenStorage):
    """In-memory token storage implementation for OAuth authentication.

    This implementation stores OAuth tokens and client information in memory.
    For production use, consider implementing persistent storage.
    """

    def __init__(self):
        """Initialize the in-memory token storage."""
        self.tokens: Optional[OAuthToken] = None
        self.client_info: Optional[OAuthClientInformationFull] = None

    async def get_tokens(self) -> Optional[OAuthToken]:
        """Get stored tokens.

        Returns:
            Optional[OAuthToken]: The stored OAuth tokens, if any.
        """
        return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        """Store tokens.

        Args:
            tokens (OAuthToken): The OAuth tokens to store.
        """
        self.tokens = tokens
        logger.debug("OAuth tokens stored in memory")

    async def get_client_info(self) -> Optional[OAuthClientInformationFull]:
        """Get stored client information.

        Returns:
            Optional[OAuthClientInformationFull]: The stored client information, if any.
        """
        return self.client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        """Store client information.

        Args:
            client_info (OAuthClientInformationFull): The client information to store.
        """
        self.client_info = client_info
        logger.debug("OAuth client info stored in memory")


class OAuthHandler:
    """OAuth handler for MCP Scanner authentication.

    This class provides utilities for handling OAuth authentication flows,
    including redirect handling and callback processing.
    """

    def __init__(self, config: Config):
        """Initialize the OAuth handler.

        Args:
            config (Config): The scanner configuration.
        """
        self.config = config

    async def handle_redirect(self, auth_url: str) -> None:
        """Handle OAuth redirect by displaying the authorization URL.

        Args:
            auth_url (str): The authorization URL to display to the user.
        """
        logger.info(f"OAuth authorization required. Visit: {auth_url}")
        print(f"Visit the following URL to authorize the application: {auth_url}")

    async def handle_callback(self) -> Tuple[str, Optional[str]]:
        """Handle OAuth callback by prompting for the callback URL.

        Returns:
            Tuple[str, Optional[str]]: A tuple containing (code, state).
        """
        callback_url = input("Paste the callback URL here: ")
        params = parse_qs(urlparse(callback_url).query)

        if "code" not in params:
            raise ValueError("Authorization code not found in callback URL")

        code = params["code"][0]
        state = params.get("state", [None])[0]

        logger.debug(f"OAuth callback processed: code received, state={state}")
        return code, state

    def create_oauth_provider(
        self,
        server_url: str,
        storage: Optional[TokenStorage] = None,
        redirect_handler: Optional[Callable[[str], None]] = None,
        callback_handler: Optional[Callable[[], Tuple[str, Optional[str]]]] = None,
    ) -> OAuthClientProvider:
        """Create an OAuth client provider with the given configuration.

        Args:
            server_url (str): The MCP server URL.
            storage (Optional[TokenStorage]): Token storage implementation. Defaults to InMemoryTokenStorage.
            redirect_handler (Optional[Callable]): Custom redirect handler. Defaults to self.handle_redirect.
            callback_handler (Optional[Callable]): Custom callback handler. Defaults to self.handle_callback.

        Returns:
            OAuthClientProvider: The configured OAuth client provider.
        """
        if storage is None:
            storage = InMemoryTokenStorage()

        if redirect_handler is None:
            redirect_handler = self.handle_redirect

        if callback_handler is None:
            callback_handler = self.handle_callback

        # Parse OAuth scopes from config or use defaults
        scopes = self.config.oauth_scopes or [CONSTANTS.OAUTH_DEFAULT_SCOPE]
        scope = " ".join(scopes)

        # Parse grant types and response types
        grant_types = CONSTANTS.OAUTH_DEFAULT_GRANT_TYPES.split(",")
        response_types = CONSTANTS.OAUTH_DEFAULT_RESPONSE_TYPES.split(",")

        # Create OAuth client metadata
        client_metadata = OAuthClientMetadata(
            client_name=CONSTANTS.OAUTH_CLIENT_NAME,
            redirect_uris=[AnyUrl(CONSTANTS.OAUTH_DEFAULT_REDIRECT_URI)],
            grant_types=grant_types,
            response_types=response_types,
            scope=scope,
        )

        logger.debug(f"Creating OAuth provider for server: {server_url}")
        logger.debug(
            f"OAuth metadata: client_name={client_metadata.client_name}, scope={scope}"
        )

        return OAuthClientProvider(
            server_url=server_url,
            client_metadata=client_metadata,
            storage=storage,
            redirect_handler=redirect_handler,
            callback_handler=callback_handler,
        )


def create_oauth_provider_from_config(
    config: Config,
    server_url: str,
    storage: Optional[TokenStorage] = None,
) -> Optional[OAuthClientProvider]:
    """Create an OAuth provider from configuration if OAuth is configured.

    Args:
        config (Config): The scanner configuration.
        server_url (str): The MCP server URL.
        storage (Optional[TokenStorage]): Token storage implementation.

    Returns:
        Optional[OAuthClientProvider]: The OAuth provider if configured, None otherwise.
    """
    # Check if OAuth is configured
    if not config.oauth_client_id:
        logger.debug("OAuth not configured (no client ID)")
        return None

    handler = OAuthHandler(config)
    return handler.create_oauth_provider(server_url, storage)


def create_oauth_provider_from_auth(
    auth: Auth,
    server_url: str,
) -> Optional[OAuthClientProvider]:
    """Create an OAuth provider from explicit Auth parameter.

    Args:
        auth (Auth): The authentication configuration.
        server_url (str): The MCP server URL.

    Returns:
        Optional[OAuthClientProvider]: The OAuth provider if OAuth is enabled, None otherwise.
    """
    if not auth or not auth.is_oauth():
        logger.debug("OAuth not enabled in Auth parameter")
        return None

    if not auth.client_id:
        raise ValueError("OAuth client_id is required when Auth.type == OAuth")

    # Use provided storage or create default
    storage = auth.storage or InMemoryTokenStorage()

    # Use provided handlers or create default ones
    redirect_handler = auth.redirect_handler
    callback_handler = auth.callback_handler

    if redirect_handler is None or callback_handler is None:
        # Create a temporary config for default handlers
        temp_config = Config()
        temp_handler = OAuthHandler(temp_config)

        if redirect_handler is None:
            redirect_handler = temp_handler.handle_redirect
        if callback_handler is None:
            callback_handler = temp_handler.handle_callback

    # Parse OAuth scopes
    scopes = auth.scopes or [CONSTANTS.OAUTH_DEFAULT_SCOPE]
    scope = " ".join(scopes)

    # Parse grant types and response types
    grant_types = CONSTANTS.OAUTH_DEFAULT_GRANT_TYPES.split(",")
    response_types = CONSTANTS.OAUTH_DEFAULT_RESPONSE_TYPES.split(",")

    # Use provided redirect URI or default
    redirect_uri = auth.redirect_uri or CONSTANTS.OAUTH_DEFAULT_REDIRECT_URI

    # Create OAuth client metadata
    client_metadata = OAuthClientMetadata(
        client_name=CONSTANTS.OAUTH_CLIENT_NAME,
        redirect_uris=[AnyUrl(redirect_uri)],
        grant_types=grant_types,
        response_types=response_types,
        scope=scope,
    )

    logger.info(f"Creating OAuth provider from Auth parameter for server: {server_url}")
    logger.debug(
        f"OAuth metadata: client_name={client_metadata.client_name}, scope={scope}"
    )

    return OAuthClientProvider(
        server_url=server_url,
        client_metadata=client_metadata,
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )


def create_bearer_auth(bearer_token: str) -> Auth:
    """Create Bearer authentication instance.

    Args:
        bearer_token (str): Bearer token.

    Returns:
        Auth: Bearer authentication instance.
    """
    return Auth(enabled=True, auth_type=AuthType.BEARER, bearer_token=bearer_token)


class BearerAuth(httpx.Auth):
    """Bearer token authentication for HTTP requests."""

    def __init__(self, token: str):
        """Initialize Bearer authentication.

        Args:
            token (str): Bearer token.
        """
        self.token = SecretStr(token)

    def auth_flow(self, request):
        """Add Bearer token to request headers.

        Args:
            request: The HTTP request to authenticate.
        """
        request.headers["Authorization"] = f"Bearer {self.token.get_secret_value()}"
        yield request

class ApiKeyAuth(httpx.Auth):
    """API Key authentication for HTTP requests."""

    def __init__(self, api_key_header: str, api_key: str):
        """Initialize API Key authentication.

        Args:
            api_key_header (str): The HTTP header name for the API key (e.g., "X-API-Key").
            api_key (str): The API key value.
        """
        self.api_key_header = api_key_header
        self.api_key = SecretStr(api_key)
    def auth_flow(self, request):
        """Add API key to request headers.

        Args:
            request: The HTTP request to authenticate.
        """
        request.headers[self.api_key_header] = self.api_key.get_secret_value()
        yield request
