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

"""Tests for the pieces of a remote MCP connect.

The HTTP-status translation in particular had no coverage: the MCP library
reports a 401/403/404 as a cancelled task or an ExceptionGroup, so the only
thing that tells a user "this server needs a token" apart from "this server
is down" is the mapping exercised here.
"""

import logging as stdlib_logging

import pytest

from mcpscanner.core.auth import Auth, AuthType
from mcpscanner.core.exceptions import (
    MCPAuthenticationError,
    MCPServerNotFoundError,
)
from mcpscanner.core.session import (
    _auth_headers,
    _capture_http_status,
    _http_status_error,
    _looks_like_connection_failure,
)

URL = "https://mcp.example.com/mcp"


class TestAuthHeaders:
    def test_no_auth_connects_anonymously(self):
        provider, headers = _auth_headers(None, URL)

        assert provider is None
        assert headers == {}

    def test_bearer_becomes_an_authorization_header(self):
        auth = Auth(enabled=True, auth_type=AuthType.BEARER, bearer_token="t0ken")

        provider, headers = _auth_headers(auth, URL)

        assert provider is None
        assert headers == {"Authorization": "Bearer t0ken"}

    def test_bearer_without_a_token_is_rejected(self):
        auth = Auth(enabled=True, auth_type=AuthType.BEARER)

        with pytest.raises(ValueError, match="no bearer_token"):
            _auth_headers(auth, URL)

    def test_apikey_uses_its_configured_header(self):
        auth = Auth(
            enabled=True,
            auth_type=AuthType.APIKEY,
            api_key="k",
            api_key_header="X-Api-Key",
        )

        _, headers = _auth_headers(auth, URL)

        assert headers == {"X-Api-Key": "k"}

    def test_apikey_without_a_header_name_is_rejected(self):
        auth = Auth(enabled=True, auth_type=AuthType.APIKEY, api_key="k")

        with pytest.raises(ValueError, match="no api key or api header"):
            _auth_headers(auth, URL)

    def test_custom_headers_ride_along_with_any_auth_type(self):
        auth = Auth(
            enabled=True,
            auth_type=AuthType.BEARER,
            bearer_token="t0ken",
            custom_headers={"X-Trace": "abc"},
        )

        _, headers = _auth_headers(auth, URL)

        assert headers == {"Authorization": "Bearer t0ken", "X-Trace": "abc"}

    def test_custom_headers_work_without_any_auth_type(self):
        auth = Auth(enabled=True, custom_headers={"X-Trace": "abc"})

        _, headers = _auth_headers(auth, URL)

        assert headers == {"X-Trace": "abc"}


class TestHttpStatusError:
    def test_401_asks_for_credentials(self):
        error = _http_status_error(401, URL)

        assert isinstance(error, MCPAuthenticationError)
        assert "--bearer-token" in str(error)

    def test_403_reports_access_denied(self):
        error = _http_status_error(403, URL)

        assert isinstance(error, MCPAuthenticationError)
        assert "Access denied" in str(error)

    def test_404_reports_a_bad_endpoint(self):
        error = _http_status_error(404, URL)

        assert isinstance(error, MCPServerNotFoundError)
        assert URL in str(error)

    @pytest.mark.parametrize("code", [None, 200, 500, 502])
    def test_other_statuses_say_nothing_useful(self, code):
        # None lets the caller pick the error that fits how the failure arrived.
        assert _http_status_error(code, URL) is None

    def test_cause_is_appended_when_one_is_known(self):
        error = _http_status_error(401, URL, cause=RuntimeError("boom"))

        assert str(error).endswith("Original error: boom")

    def test_cause_is_omitted_when_there_is_none(self):
        assert "Original error" not in str(_http_status_error(401, URL))


class TestLooksLikeConnectionFailure:
    @pytest.mark.parametrize(
        "error",
        [
            ConnectionError("connection refused"),
            OSError("nodename nor servname provided"),
            RuntimeError("Connection reset by peer"),
        ],
    )
    def test_recognises_unreachable_hosts(self, error):
        assert _looks_like_connection_failure(error)

    def test_leaves_unrelated_errors_alone(self):
        assert not _looks_like_connection_failure(ValueError("bad tool schema"))


class TestCaptureHttpStatus:
    def test_records_a_status_httpx_logged(self):
        logger = stdlib_logging.getLogger("httpx")

        with _capture_http_status() as probe:
            logger.info('HTTP Request: GET %s "HTTP/1.1 401 Unauthorized"', URL)

        assert probe.code == 401

    def test_stays_none_when_nothing_interesting_is_logged(self):
        logger = stdlib_logging.getLogger("httpx")

        with _capture_http_status() as probe:
            logger.info('HTTP Request: GET %s "HTTP/1.1 200 OK"', URL)

        assert probe.code is None

    def test_restores_the_logger_it_borrowed(self):
        logger = stdlib_logging.getLogger("httpx")
        logger.setLevel(stdlib_logging.WARNING)
        logger.propagate = True
        handlers_before = list(logger.handlers)

        with _capture_http_status():
            pass

        assert logger.level == stdlib_logging.WARNING
        assert logger.propagate is True
        assert logger.handlers == handlers_before

    def test_restores_the_logger_even_when_the_body_raises(self):
        logger = stdlib_logging.getLogger("httpx")
        logger.setLevel(stdlib_logging.WARNING)
        handlers_before = list(logger.handlers)

        with pytest.raises(RuntimeError):
            with _capture_http_status():
                raise RuntimeError("connect blew up")

        assert logger.level == stdlib_logging.WARNING
        assert logger.handlers == handlers_before
