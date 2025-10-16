//////////////////////////////////////////
// Shell/System Command Injection Detection Rule
// Target: Command injection patterns for MCP environments
// (Shell operators, dangerous commands, network tools + evasion)
/////////////////////////////////////////

rule command_injection{

    meta:
        author = "Cisco"
        description = "Detects command injection patterns related to shell operators, system commands, and network tools"
        classification = "harmful"
        threat_type = "INJECTION ATTACK"

    strings:

        // Dangerous system commands
        $dangerous_system_cmds = /\b(shutdown|reboot|halt)\s+(-[fh]|now|0)\b/

        // Network tools with suspicious usage patterns
        $malicious_network_tools = /\b(nc|netcat)\s+(-[le]|25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/i

        // Reconnaissance tools
        $reconnaissance_tools = /\b(nmap)\s+(-[sS]|--script|25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/i

        // Data exfiltration tools
        $data_exfiltration_tools = /\b(wget|curl)\s+(http[s]?:\/\/|ftp:\/\/|-[oO]\b|--output\b)/i

        // ANSI escape codes for terminal manipulation
        $ansi_escape_codes = /\\u001b\[[0-9;]*m/

        // Reverse shell patterns
        $reverse_shells = /\b(bash\s+-i|sh\s+-i|nc\s+-e|\/dev\/tcp|socat.*exec)\b/i

        // Windows commands
        $windows_cmds = /\b(cmd\s*\/[ck]|powershell|net\s+user|reg\s+|wmic|rundll32\b)/i

    condition:

        // Dangerous system command patterns
        $dangerous_system_cmds or

        // Network tool abuse patterns
        $malicious_network_tools or

        // Reconnaissance tools
        $reconnaissance_tools or

        // Data exfiltration tools
        $data_exfiltration_tools or

        // Terminal manipulation
        $ansi_escape_codes or

        // Reverse shell patterns
        $reverse_shells or

        // Windows commands
        $windows_cmds
}
