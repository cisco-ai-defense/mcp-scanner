// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: XPath injection — user-controlled fragments folded into an XPath expression.

using System.Collections.Generic;
using System.ComponentModel;
using ModelContextProtocol.Server;

namespace EvalSamples.InjectionAttacks;

[McpServerToolType]
public static class XpathInjectionDynamicQueryTool
{
    private sealed class XMLQueryBuilder(string xmlFile = "users.xml")
    {
        private object? Tree { get; set; }

        public void LoadXml()
        {
            _ = xmlFile;
            Tree = new object();
        }

        public string BuildXPath(string element, IDictionary<string, string> conditions, string logicalOp = "and")
        {
            if (conditions.Count == 0) return $"//{element}";
            var preds = new List<string>();
            foreach (var kv in conditions)
            {
                // VULNERABLE: No escaping of XPath special characters
                preds.Add($"@{kv.Key}='{kv.Value}'");
            }
            var conditionStr = string.Join($" {logicalOp} ", preds);
            return $"//{element}[{conditionStr}]";
        }

        public List<object> ExecuteQuery(string xpathQuery)
        {
            _ = Tree;
            _ = xpathQuery;
            return [];
        }
    }

    [McpServerTool]
    [Description("Query XML database for user records with flexible filtering.")]
    public static string QueryXml(
        string user_id = "",
        string username = "",
        string role = "",
        bool match_all = true,
        bool include_inactive = false)
    {
        var builder = new XMLQueryBuilder();
        builder.LoadXml();

        var conditions = new Dictionary<string, string>();
        if (!string.IsNullOrEmpty(user_id)) conditions["id"] = user_id;
        if (!string.IsNullOrEmpty(username)) conditions["name"] = username;
        if (!string.IsNullOrEmpty(role)) conditions["role"] = role;
        if (!include_inactive) conditions["status"] = "active";

        var logicalOp = match_all ? "and" : "or";
        var xpathQuery = builder.BuildXPath("user", conditions, logicalOp);
        var results = builder.ExecuteQuery(xpathQuery);
        var n = results.Count > 0 ? results.Count : conditions.Count;
        return $"Found {n} records matching XPath: {xpathQuery}";
    }
}
