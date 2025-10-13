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

import asyncio
import urllib.parse
import urllib.request
from typing import Tuple, Optional

from mcpscanner import Config, Scanner
from mcpscanner.core.auth import Auth
from mcpscanner.core.models import AnalyzerEnum

OAUTH_BASE = "http://127.0.0.1:9001"
REDIRECT_URI = f"{OAUTH_BASE}/callback"
CLIENT_ID = "test-client"
CLIENT_SECRET = "test-secret"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_auth_code_and_state(auth_url: str) -> Tuple[str, Optional[str]]:
    """
    Programmatically hit the authorize endpoint and capture the 302 Location to extract code/state.
    """
    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(auth_url)
    except urllib.error.HTTPError as e:
        # Expecting 302 with Location header
        if e.code not in (302, 303):
            raise
        location = e.headers.get("Location")
        if not location:
            raise RuntimeError("No Location header in authorize redirect")
        parsed = urllib.parse.urlparse(location)
        query = urllib.parse.parse_qs(parsed.query)
        code = query.get("code", [None])[0]
        state = query.get("state", [None])[0]
        if not code:
            raise RuntimeError("No code in authorize redirect")
        return code, state
    raise RuntimeError("Authorize did not redirect as expected")


async def main():
    cfg = Config()
    scanner = Scanner(cfg)

    # The OAuth provider will call this with a fully formed authorize URL from the server
    code_holder = {"code": None, "state": None}

    async def redirect_handler(auth_url: str) -> None:
        code, state = get_auth_code_and_state(auth_url)
        code_holder["code"] = code
        code_holder["state"] = state

    async def callback_handler() -> Tuple[str, Optional[str]]:
        # Wait briefly for redirect handler to populate values
        retries = 0
        while code_holder["code"] is None and retries < 50:
            await asyncio.sleep(0.05)
            retries += 1
        if code_holder["code"] is None:
            raise RuntimeError("OAuth code not available; redirect handler did not run")
        return code_holder["code"], code_holder["state"]

    auth = Auth.oauth(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scopes=["tools.read"],
        redirect_uri=REDIRECT_URI,
        redirect_handler=redirect_handler,  # programmatically hit authorize
        callback_handler=callback_handler,
    )

    results = await scanner.scan_remote_server_tools(
        "http://127.0.0.1:9001/sse",
        auth=auth,
        analyzers=[AnalyzerEnum.YARA],
    )

    print(f"Scanned tools: {len(results)}")
    for r in results:
        print(f"- {r.tool_name}: {len(r.findings)} findings")


if __name__ == "__main__":
    asyncio.run(main())
