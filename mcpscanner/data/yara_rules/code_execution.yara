//////////////////////////////////////////
// Programming Language Code Exec Detection Rule
// Target: Code exec funcs for primary MCP Server languages
// (Python, JavaScript/TypeScript, PHP + generic patterns)
/////////////////////////////////////////

rule code_execution{

    meta:

        author = "Cisco"
        description = "Detects code execution functions in MCP implementations focusing on Scripts - the primary languages used in agentic servers"
        classification = "harmful"
        threat_type = "CODE EXECUTION"

    strings:

        // Generic cross-language execution calls (catch-all safety net)
        $generic_exec_calls = /\b(system|exec(file)?|popen|spawn|eval|compile|shell_exec|passthru|proc_open)\s*\(/i

        // Python specific execution calls
        $python_exec_calls = /\b(os\.(system|popen|spawn|execv?p?e?|spawnv?p?e?)|subprocess\.|__import__)\s*\(/i

        // JS or TS specific execution calls
        $js_ts_exec_calls = /\b(child_process\b|Function\s*\(|vm\.(runInThisContext|runInNewContext|createScript))/i

        // PHP specific execution calls
        $php_exec_calls = /\b(popen|assert|create_function|call_user_func(_array)?|preg_replace[^\s]*\/)/i

        // Base64 decode for code obfuscation
        $code_obfuscation = /\b(base64\.(b64)?decode(bytes)?|(atob|btoa)\s*\(|Buffer\.from\s*\(|Convert\.FromBase64String|Base64::decode|uuencode|eval\s+(base64|\$|\`))/i

        // Code Dumping
        $code_dumping = /\b(xxd\s+-r|hexdump|printf\s+\\x|echo\s+-e)\b/i

    condition:

        // Python execution calls
        $python_exec_calls or

        // JS or TS execution calls
        $js_ts_exec_calls or

        // PHP execution calls
        $php_exec_calls or

        // Generic execution calls
        $generic_exec_calls or

        // Code obfuscation patterns
        $code_obfuscation or

        // Code dumping and evasion techniques
        $code_dumping
}
