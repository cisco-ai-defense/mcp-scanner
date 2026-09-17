# Copyright 2026 Cisco Systems, Inc. and its affiliates
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

"""Credentials must never reach the log.

Logs travel further than the process that wrote them -- into aggregators,
support bundles, CI artifacts -- so a secret written at DEBUG is a secret
disclosed. The Auth object carries a client secret, a bearer token and an
API key alongside harmless fields like scopes, which makes it easy for a
later edit to log the wrong attribute while looking entirely reasonable.

These tests drive the provider-construction paths with recognisable
sentinel values and fail if any of them appear in captured output.
"""

import logging

import pytest

from mcpscanner.core.auth import Auth, AuthType, create_oauth_provider_from_auth

SECRETS = {
    "client_secret": "sk_live_CLIENTSECRETSENTINEL",
    "bearer_token": "BEARERTOKENSENTINEL",
    "api_key": "APIKEYSENTINEL",
}


@pytest.fixture
def auth_logs(caplog):
    """Capture this module's records; mcpscanner loggers do not propagate."""
    from mcpscanner.core import auth as auth_module

    logger = auth_module.logger
    previous = logger.propagate
    logger.propagate = True
    caplog.set_level(logging.DEBUG, logger=logger.name)
    yield caplog
    logger.propagate = previous


def loaded_auth(**overrides):
    """An Auth carrying every credential field, plus OAuth config."""
    return Auth(
        enabled=True,
        auth_type=AuthType.OAUTH,
        client_id="client-id-not-secret",
        scopes=["user:read", "user:write"],
        redirect_uri="http://localhost:8080/callback",
        **{**SECRETS, **overrides},
    )


def assert_no_secrets(caplog):
    """Fail naming the credential that leaked, not just that one did."""
    text = caplog.text
    leaked = [name for name, value in SECRETS.items() if value in text]
    assert not leaked, f"credentials written to the log: {', '.join(leaked)}"


class TestOAuthProviderConstruction:
    def test_no_credential_is_logged(self, auth_logs):
        create_oauth_provider_from_auth(loaded_auth(), "https://mcp.example.com")
        assert_no_secrets(auth_logs)

    def test_something_is_still_logged(self, auth_logs):
        """Guard against the assertion above passing because nothing ran."""
        create_oauth_provider_from_auth(loaded_auth(), "https://mcp.example.com")
        assert auth_logs.text.strip()

    def test_the_server_url_is_still_recorded(self, auth_logs):
        """The diagnostic value of these lines has to survive the redaction."""
        create_oauth_provider_from_auth(loaded_auth(), "https://mcp.example.com")
        assert "mcp.example.com" in auth_logs.text

    def test_scope_count_is_reported_without_the_scopes(self, auth_logs):
        create_oauth_provider_from_auth(loaded_auth(), "https://mcp.example.com")
        assert "scope_count=2" in auth_logs.text

    def test_a_secret_smuggled_into_a_scope_is_not_echoed(self, auth_logs):
        """Scopes are attacker-influencable config; they are not echoed back."""
        auth = loaded_auth()
        auth.scopes = ["user:read", SECRETS["client_secret"]]
        create_oauth_provider_from_auth(auth, "https://mcp.example.com")
        assert_no_secrets(auth_logs)

    def test_disabled_auth_logs_no_credential(self, auth_logs):
        auth = loaded_auth()
        auth.enabled = False
        create_oauth_provider_from_auth(auth, "https://mcp.example.com")
        assert_no_secrets(auth_logs)

    def test_the_client_id_error_path_leaks_nothing(self, auth_logs):
        """The rejection raises; neither the log nor the message may carry a secret."""
        auth = loaded_auth()
        auth.client_id = None
        with pytest.raises(ValueError) as exc:
            create_oauth_provider_from_auth(auth, "https://mcp.example.com")
        assert_no_secrets(auth_logs)
        assert not [n for n, v in SECRETS.items() if v in str(exc.value)]


class TestConfigDrivenProviderConstruction:
    """The same construction reached through Config rather than Auth."""

    def handler(self):
        from mcpscanner.config.config import Config
        from mcpscanner.core.auth import OAuthHandler

        return OAuthHandler(
            Config(
                api_key="unused",
                oauth_client_id="client-id-not-secret",
                oauth_client_secret=SECRETS["client_secret"],
                oauth_scopes=["user:read", "user:write"],
            )
        )

    def test_no_credential_is_logged(self, auth_logs):
        self.handler().create_oauth_provider("https://mcp.example.com")
        assert_no_secrets(auth_logs)

    def test_scope_count_is_reported_without_the_scopes(self, auth_logs):
        self.handler().create_oauth_provider("https://mcp.example.com")
        assert "scope_count=2" in auth_logs.text


class TestAuthReprDoesNotLeak:
    """A bare Auth in an f-string or %s must not spill its contents."""

    def test_repr_hides_the_credentials(self):
        text = repr(loaded_auth())
        leaked = [n for n, v in SECRETS.items() if v in text]
        assert not leaked, f"repr(Auth) exposes: {', '.join(leaked)}"

    def test_str_hides_the_credentials(self):
        text = str(loaded_auth())
        leaked = [n for n, v in SECRETS.items() if v in text]
        assert not leaked, f"str(Auth) exposes: {', '.join(leaked)}"
