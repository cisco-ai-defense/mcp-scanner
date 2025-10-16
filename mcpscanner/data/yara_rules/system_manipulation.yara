//////////////////////////////////////////
// System Manipulation and Privilege Escalation Detection
// Target: File destruction and manipulation operations
// (Process control and termination)
//////////////////////////////////////////

rule system_manipulation{

    meta:
        author = "Cisco"
        description = "Detects system manipulation, privilege escalation, and destructive file operations"
        classification = "harmful"
        threat_type = "SYSTEM MANIPULATION"

    strings:
        // System environment and path access patterns
        $sys_env_access = /(\$(PATH|HOME|USER|SHELL|PWD)|process\.env|os\.environ|getenv\s*\()/i

        // File destruction and manipulation
        $file_destruction = /\b(rm\s+-rf?\b|del\s+.*\/[is]|dd\s+if=|wipefs\b|shred\s|find\s+.*-delete\b)/i

        // File permission manipulation
        $permission_manipulation = /\b(chmod\s+(777|4755|6755|[ug]?\+s)|(chown|chgrp)\s+(root|0)|setuid|setgid)\b/i

        // System directory and file access
        $critical_system_access = /(\/etc\/(passwd|pwd|shadow|hosts)\/|(\/usr)?\/s?bin\/|\/(tmp|var|root)\/|C:\\\\Windows\\\\System32\b)/i

        // Privilege escalation patterns
        $privilege_escalation = /\b(sudo\s+.*-[si]|su\s+-|runuser\b|doas\b)/i

        // Process control and termination
        $process_manipulation = /\b(kill\s+(-9\s+[0-9]+|1)|killall\s*(-9)?|pkill\s+-f|pgrep\s+-f|pidof|lsof)\b/i

        // Dangerous wildcard and recursive operations
        $recursive_operations = /\b(rm\s+[^*]*\*|del\s+[^\*]*\*|find\s+.*-exec\b)/i

    condition:

        // System environment access
        $sys_env_access or

        // File destruction and manipulation
        $file_destruction or

        // File permission manipulation
        $permission_manipulation or

        // Critical system access
        $critical_system_access or

        // Privilege escalation
        $privilege_escalation or

        // Process manipulation
        $process_manipulation or

        // Recursive/wildcard operations
        $recursive_operations
}
