// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: NoSQL injection — BSON-style query document assembled from JSON merge (find is stubbed).

using System.Collections.Generic;
using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;

namespace EvalSamples.InjectionAttacks;

[McpServerToolType]
public static class NosqlInjectionMongodbTool
{
    private sealed class MongoDBQueryBuilder
    {
        public Dictionary<string, object> BuildQuery(Dictionary<string, object> filters, bool useOperators)
        {
            var query = new Dictionary<string, object>();
            foreach (var kv in filters)
            {
                if (useOperators && kv.Value is string s)
                {
                    try
                    {
                        var parsed = JsonSerializer.Deserialize<JsonElement>(s);
                        query[kv.Key] = parsed;
                        continue;
                    }
                    catch { /* swallow */ }
                }
                query[kv.Key] = kv.Value;
            }
            return query;
        }

        public List<object> FindDocuments(Dictionary<string, object> query, int limit)
        {
            _ = query;
            _ = limit;
            return [];
        }
    }

    [McpServerTool]
    [Description("Find documents in MongoDB collection with flexible query options.")]
    public static string FindDocuments(
        string username = "",
        string email = "",
        string role = "",
        string custom_query = "",
        bool use_regex = false,
        int limit = 100)
    {
        var builder = new MongoDBQueryBuilder();
        var filters = new Dictionary<string, object>();

        if (!string.IsNullOrEmpty(username))
        {
            if (use_regex)
                filters["username"] = new Dictionary<string, object> { ["$regex"] = username };
            else
                filters["username"] = username;
        }
        if (!string.IsNullOrEmpty(email)) filters["email"] = email;
        if (!string.IsNullOrEmpty(role)) filters["role"] = role;

        if (!string.IsNullOrEmpty(custom_query))
        {
            try
            {
                var custom = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(custom_query);
                if (custom != null)
                {
                    foreach (var kv in custom)
                        filters[kv.Key] = kv.Value;
                }
            }
            catch { /* swallow */ }
        }

        var query = builder.BuildQuery(filters, useOperators: true);
        var results = builder.FindDocuments(query, limit);
        var enc = JsonSerializer.Serialize(query);
        return $"Found {results.Count} documents matching query: {enc}";
    }
}
