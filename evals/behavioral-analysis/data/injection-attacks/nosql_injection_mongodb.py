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

"""Example 7: Complex NoSQL Injection with MongoDB Query Operators"""
from mcp import FastMCP
import json

app = FastMCP("injection-attacks-service-7")

class MongoDBQueryBuilder:
    """Builds and executes MongoDB queries"""
    def __init__(self, connection_string: str = "mongodb://localhost:27017/"):
        self.connection_string = connection_string
        self.db_name = "mydb"
        self.collection_name = "users"
    
    def build_query(self, filters: dict, use_operators: bool = False) -> dict:
        """Build MongoDB query from filters"""
        query = {}
        
        for field, value in filters.items():
            if use_operators and isinstance(value, str):
                # Try to parse as JSON for operator queries
                try:
                    parsed_value = json.loads(value)
                    query[field] = parsed_value
                except:
                    query[field] = value
            else:
                query[field] = value
        
        return query
    
    def find_documents(self, query: dict, projection: dict = None,
                      sort_field: str = None, limit: int = 100) -> list:
        """Execute MongoDB find query"""
        from pymongo import MongoClient
        
        try:
            client = MongoClient(self.connection_string)
            db = client[self.db_name]
            collection = db[self.collection_name]
            
            # Build query options
            cursor = collection.find(query, projection)
            
            if sort_field:
                cursor = cursor.sort(sort_field, 1)
            
            if limit:
                cursor = cursor.limit(limit)
            
            # VULNERABLE: Directly executing user-controlled query
            results = list(cursor)
            
            client.close()
            return results
        except Exception as e:
            return []

@app.tool()
def find_documents(username: str = "",
                  email: str = "",
                  role: str = "",
                  custom_query: str = "",
                  use_regex: bool = False,
                  limit: int = 100) -> str:
    """
    Find documents in MongoDB collection with flexible query options.
    """
    builder = MongoDBQueryBuilder()
    
    # Build query filters
    filters = {}
    
    if username:
        if use_regex:
            # VULNERABLE: NoSQL injection via regex
            filters["username"] = {"$regex": username}
        else:
            filters["username"] = username
    
    if email:
        filters["email"] = email
    
    if role:
        filters["role"] = role
    
    # VULNERABLE: Custom query allows injection of MongoDB operators
    # User can inject: '{"$ne": null}' to bypass authentication
    # Or: '{"$gt": ""}' to return all documents
    # Or: '{"$where": "this.password.length > 0"}' for JavaScript injection
    if custom_query:
        try:
            custom_filters = json.loads(custom_query)
            filters.update(custom_filters)
        except:
            pass
    
    # Build final query
    query = builder.build_query(filters, use_operators=True)
    
    # Execute query
    results = builder.find_documents(query, limit=limit)
    
    return f"Found {len(results)} documents matching query: {json.dumps(query)}"
