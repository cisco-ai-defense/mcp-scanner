//////////////////////////////////////////
// Detects common scripting payloads (JS, VBScript, etc.) embeddings.
// Target: JavaScript, VBScript, or ActiveX payloads.
// (Event handlers or inline scripts)
//////////////////////////////////////////

rule script_injection{

    meta:
        author = "Cisco"
        description = "Detects embedded scripting payloads (JS, VBScript, etc.) in MCP tool descriptions"
        classification = "harmful"
        threat_type = "INJECTION ATTACK"

    strings:

        // Script tags and protocol handlers
        $tags = /(<\/?script[^>]*>|javascript:)/i

        // Execution functions
        $execution_functions = /\b(setTimeout|Function|setInterval)\s*\(/i

        // VBScript execution and Windows Script Host objects
        $vbs_execution = /\b(vbscript|CreateObject|WScript\.Shell|Shell\.Application)\b/i

        // VBScript dangerous functions
        $vbs_dangerous_functions = /\b(Exec|Run|ShellExecute)\s*\(/i

        // Base64 encoded script data URIs
        $encoded_script_uris = /\bdata:(text\/html|application\/javascript);base64\b/i

        // ANSI terminal deception patterns
        $ansi_deception = /(\\x1[Bb]\[38;5;\d+|\\x1[Bb]\[2F\\x1[Bb]\[1G|\\x1[Bb]\[1;1H\\x1[Bb]\[0J|\\x1[Bb]\]8;;.*\\x1[Bb]\\|\\033\[[0-9;]*m|\\e\[[0-9;]*[mGKHF])/i

        // Hidden instruction obfuscation
        $hidden_obfuscation = /\b(padding.*push.*off.*screen|hidden.*scrollbar|overflow.*hidden.*instruction|invisible.*text.*color)\b/i

    condition:

        // Script tags and protocol handlers
        $tags or

        // Execution functions
        $execution_functions or

        // VBScript execution
        $vbs_execution or

        // VBScript dangerous functions
        $vbs_dangerous_functions or

        // Base64 encoded script URIs
        $encoded_script_uris or

        // ANSI terminal deception
        $ansi_deception or

        // Hidden instruction obfuscation
        $hidden_obfuscation

}
