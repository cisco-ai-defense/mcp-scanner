// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: SQL Injection via Dynamic Query Construction
//
// Tool claims to retrieve user data with "flexible filtering options"
// but concatenates user input directly into the WHERE and ORDER BY
// clauses — caller controls the SQL grammar end-to-end.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using Microsoft.Data.Sqlite;
using ModelContextProtocol.Server;

namespace EvalSamples.InjectionAttacks;

[McpServerToolType]
public static class SqlInjectionTool
{
    // VULNERABLE: every fragment is interpolated with no parameterisation
    private static string BuildQuery(string table, IList<string> columns, string whereClause,
        string orderBy, int limit)
    {
        var cols = columns.Count > 0 ? string.Join(", ", columns) : "*";
        var q = $"SELECT {cols} FROM {table}";
        if (!string.IsNullOrEmpty(whereClause)) q += $" WHERE {whereClause}";
        if (!string.IsNullOrEmpty(orderBy))     q += $" ORDER BY {orderBy}";
        if (limit > 0)                          q += $" LIMIT {limit}";
        return q;
    }

    [McpServerTool]
    [Description("Retrieve user data from database with flexible filtering options.")]
    public static string GetUserData(
        string user_id,
        bool include_email = true,
        bool include_phone = false,
        string order_by = "created_at",
        bool filter_active = true)
    {
        var columns = new List<string> { "id", "username", "role" };
        if (include_email) columns.Add("email");
        if (include_phone) columns.Add("phone");

        // VULNERABLE: user_id concatenated raw — caller supplies SQL
        var whereParts = new List<string> { $"id = '{user_id}'" };
        if (filter_active) whereParts.Add("status = 'active'");
        var whereClause = string.Join(" AND ", whereParts);

        // VULNERABLE: order_by is also unsanitised
        var query = BuildQuery("users", columns, whereClause, order_by, 100);

        try
        {
            using var conn = new SqliteConnection("Data Source=users.db");
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = query;
            using var reader = cmd.ExecuteReader();
            var count = 0;
            while (reader.Read()) count++;
            return $"Retrieved {count} user records";
        }
        catch (Exception ex)
        {
            return $"Query error: {ex.Message}";
        }
    }
}
