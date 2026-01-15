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

"""Example 6: Complex XPath Injection with Dynamic Query Construction"""
from mcp import FastMCP

app = FastMCP("injection-attacks-service-6")


class XMLQueryBuilder:
    """Builds and executes XPath queries"""

    def __init__(self, xml_file: str = "users.xml"):
        self.xml_file = xml_file
        self.tree = None

    def load_xml(self):
        from lxml import etree

        self.tree = etree.parse(self.xml_file)

    def build_xpath(
        self, element: str, conditions: dict, logical_op: str = "and"
    ) -> str:
        """Build XPath query from conditions"""
        if not conditions:
            return f"//{element}"

        # Build condition predicates
        predicates = []
        for attr, value in conditions.items():
            # VULNERABLE: No escaping of XPath special characters
            predicates.append(f"@{attr}='{value}'")

        condition_str = f" {logical_op} ".join(predicates)
        return f"//{element}[{condition_str}]"

    def execute_query(self, xpath_query: str) -> list:
        """Execute XPath query"""
        if not self.tree:
            self.load_xml()

        # VULNERABLE: Unsanitized XPath query execution
        return self.tree.xpath(xpath_query)


@app.tool()
def query_xml(
    user_id: str = "",
    username: str = "",
    role: str = "",
    match_all: bool = True,
    include_inactive: bool = False,
) -> str:
    """
    Query XML database for user records with flexible filtering.
    """
    builder = XMLQueryBuilder()
    builder.load_xml()

    # Build query conditions
    conditions = {}

    if user_id:
        conditions["id"] = user_id

    if username:
        conditions["name"] = username

    if role:
        conditions["role"] = role

    if not include_inactive:
        conditions["status"] = "active"

    # VULNERABLE: XPath injection through condition values
    # User can inject: "1' or '1'='1" to bypass authentication
    # Or: "1'] | //password | //user[@id='1" to extract all passwords
    logical_op = "and" if match_all else "or"
    xpath_query = builder.build_xpath("user", conditions, logical_op)

    # Execute query
    results = builder.execute_query(xpath_query)

    return f"Found {len(results)} records matching XPath: {xpath_query}"
