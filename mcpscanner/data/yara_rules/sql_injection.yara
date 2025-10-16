//////////////////////////////////////////
// SQL Injection Detection Rule
// Target: SQL keywords and operations, SQL tautologies and bypasses, Database-specific functions
//////////////////////////////////////////

rule sql_injection{

    meta:
        author = "Cisco"
        description = "Detects SQL injection attack patterns including keywords, tautologies, and database functions"
        classification = "harmful"
        threat_type = "INJECTION ATTACK"

    strings:

        // SQL injection tautologies and bypasses
        $injection_tautologies = /(OR\s+1=1|'\s*OR\s*'|"\s*OR\s*"|OR\s+'1'='1'|OR\s+"1"="1"|'\s*OR\s+1=1--|"\s*OR\s+1=1--)/i

        // Destructive SQL injections
        $destructive_injections = /(';\s*DROP\s+TABLE|";\s*DROP\s+TABLE)/i

        // Union-based SQL injection
        $union_based_attacks = /(UNION\s+(ALL\s+)?SELECT|'\s*UNION\s+SELECT|"\s*UNION\s+SELECT)/i

        // SQL information gathering functions
        $sql_info_functions = /\b(CONCAT|SUBSTRING|ASCII|CHAR|LENGTH|DATABASE|VERSION|USER)\s*\(|@@(VERSION|SERVERNAME)/i

        // Time-based blind injection techniques
        $time_based_injections = /\b(SLEEP|WAITFOR\s+DELAY|BENCHMARK|pg_sleep)\s*\(/i

        // Error-based injection methods
        $error_based_techniques = /\b(EXTRACTVALUE|UPDATEXML|EXP\(~\(SELECT|CAST)\s*\(/i

        // Database-specific system objects
        $database_system_objects = /\b(information_schema|mysql\.user|LOAD_FILE\(|INTO\s+OUTFILE|sys\.(databases|tables)|xp_cmdshell|sp_executesql|dual|all_tables|user_tables|dbms_|pg_(database|user)|current_(database|user))\b/i

        // Legitimate SQL operation patterns
        $legitimate_sql_ops = /(query_builder|sql_builder|orm_query|select_fields|insert_data|update_data|database_query|db_query|execute_query|prepared_statement|parameterized_query|SELECT\s+\*\s+FROM\s+[a-zA-Z_]+\s+WHERE)/

    condition:

        // SQL injection tautologies
        ($injection_tautologies and not $legitimate_sql_ops) or

        // Destructive SQL injections
        ($destructive_injections and not $legitimate_sql_ops) or

        // Union-based attacks
        ($union_based_attacks and not $legitimate_sql_ops) or

        // SQL information gathering functions
        ($sql_info_functions and not $legitimate_sql_ops) or

        // Time-based blind injection
        ($time_based_injections and not $legitimate_sql_ops) or

        // Error-based injection techniques
        ($error_based_techniques and not $legitimate_sql_ops) or

        // Database system object access
        ($database_system_objects and not $legitimate_sql_ops)
}
