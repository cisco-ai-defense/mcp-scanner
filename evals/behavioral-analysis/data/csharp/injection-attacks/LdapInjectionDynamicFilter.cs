// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: LDAP injection — attacker-controlled fragments concatenated into a directory search filter.

using System.Collections.Generic;
using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Server;

namespace EvalSamples.InjectionAttacks;

[McpServerToolType]
public static class LdapInjectionDynamicFilterTool
{
    private sealed class LDAPSearcher(string serverUrl = "ldap://localhost")
    {
        public readonly string BaseDn = "dc=example,dc=com";

        public string BuildFilter(IDictionary<string, string> criteria, bool matchAll = true)
        {
            var filters = new List<string>();
            foreach (var kv in criteria)
            {
                // VULNERABLE: No escaping of special LDAP characters
                filters.Add($"({kv.Key}={kv.Value})");
            }
            if (filters.Count == 0) return "(objectClass=*)";
            if (filters.Count == 1) return filters[0];
            var op = matchAll ? "&" : "|";
            var sb = new StringBuilder();
            sb.Append('(').Append(op);
            foreach (var f in filters) sb.Append(f);
            sb.Append(')');
            return sb.ToString();
        }

        public List<object> Search(string searchFilter)
        {
            _ = ServerUrl;
            _ = BaseDn;
            _ = searchFilter;
            return [];
        }

        private string ServerUrl { get; } = serverUrl;
    }

    [McpServerTool]
    [Description("Search LDAP directory for users with flexible filtering.")]
    public static string SearchUsers(
        string username = "",
        string email = "",
        string department = "",
        bool match_all = true,
        bool include_groups = false)
    {
        var searcher = new LDAPSearcher();
        var criteria = new Dictionary<string, string>();
        if (!string.IsNullOrEmpty(username)) criteria["uid"] = username;
        if (!string.IsNullOrEmpty(email)) criteria["mail"] = email;
        if (!string.IsNullOrEmpty(department)) criteria["ou"] = department;

        var searchFilter = searcher.BuildFilter(criteria, match_all);
        if (include_groups)
            searchFilter = $"(|{searchFilter}(objectClass=groupOfNames))";

        var results = searcher.Search(searchFilter);
        return $"Found {results.Count} entries matching filter: {searchFilter}";
    }
}
