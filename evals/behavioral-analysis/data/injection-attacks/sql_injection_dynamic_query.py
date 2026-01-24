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

"""Example 2: Complex SQL Injection with Dynamic Query Building"""
from mcp import FastMCP
import sqlite3

app = FastMCP("injection-attacks-service-2")


class DatabaseManager:
    """Manages database operations"""

    def __init__(self, db_path: str = "users.db"):
        self.db_path = db_path
        self.conn = None

    def connect(self):
        self.conn = sqlite3.connect(self.db_path)
        return self.conn.cursor()

    def close(self):
        if self.conn:
            self.conn.close()

    def build_query(
        self,
        table: str,
        columns: list,
        where_clause: str,
        order_by: str = None,
        limit: int = None,
    ) -> str:
        # Build SELECT query dynamically
        cols = ", ".join(columns) if columns else "*"
        query = f"SELECT {cols} FROM {table}"

        if where_clause:
            query += f" WHERE {where_clause}"

        if order_by:
            query += f" ORDER BY {order_by}"

        if limit:
            query += f" LIMIT {limit}"

        return query


@app.tool()
def get_user_data(
    user_id: str,
    include_email: bool = True,
    include_phone: bool = False,
    order_by: str = "created_at",
    filter_active: bool = True,
) -> str:
    """
    Retrieve user data from database with flexible filtering options.
    """
    db = DatabaseManager()
    cursor = db.connect()

    # Build column list
    columns = ["id", "username", "role"]
    if include_email:
        columns.append("email")
    if include_phone:
        columns.append("phone")

    # VULNERABLE: SQL injection through string concatenation in WHERE clause
    where_parts = [f"id = '{user_id}'"]

    if filter_active:
        where_parts.append("status = 'active'")

    where_clause = " AND ".join(where_parts)

    # VULNERABLE: SQL injection in ORDER BY clause
    # User can inject: "id; DROP TABLE users; --"
    query = db.build_query("users", columns, where_clause, order_by, limit=100)

    try:
        # VULNERABLE: Execute unsanitized query
        cursor.execute(query)
        results = cursor.fetchall()

        db.close()
        return f"Retrieved {len(results)} user records"
    except Exception as e:
        db.close()
        return f"Query error: {str(e)}"
