//////////////////////////////////////////
// Data Exfiltration Detection Rule
// Target: Tools that send data to external servers, hidden data collection
//////////////////////////////////////////

rule data_exfiltration{

    meta:
        author = "Cisco"
        description = "Detects data exfiltration patterns - sending data to external servers, hidden uploads, remote storage"
        classification = "harmful"
        threat_type = "DATA EXFILTRATION"

    strings:

        ////////////////////////////////////////////////
        // External server communication patterns
        ////////////////////////////////////////////////

        // Upload/send to external URLs
        $upload_external = /\b(upload|send|post|transmit|forward|sync|backup|store|save|push|export|transfer)(s|ing|ed)?\s+(to|data\s+to|files?\s+to|all|everything)?\s*(https?:\/\/|wss?:\/\/|external|remote|cloud|server)/i

        // Suspicious domain patterns in descriptions
        $suspicious_domains = /\b(attacker|evil|malware|collect|exfil|steal|hack|malicious|c2|command-?and-?control)\.(com|net|org|io|xyz)\b/i

        // External endpoint patterns
        $external_endpoints = /\b(external\s+(endpoint|server|api|service)|remote\s+(server|endpoint|api|storage)|third[- ]party\s+(server|service))\b/i

        // Data collection to remote
        $remote_collection = /\b(collect|gather|aggregate|compile|harvest)(s|ing|ed)?\s+(and\s+)?(send|upload|transmit|forward|sync|store)/i

        ////////////////////////////////////////////////
        // Hidden/covert data transfer patterns
        ////////////////////////////////////////////////

        // Invisible/hidden data transfer
        $hidden_transfer = /\b(invisibly|silently|covertly|secretly|without\s+(user\s+)?knowledge|behind\s+the\s+scenes|in\s+the\s+background)\s+(send|upload|transmit|transfer|sync|store|collect)/i

        // Never tell/inform user patterns
        $hide_from_user = /\b(never|don't|do\s+not)\s+(tell|inform|mention|notify|alert)\s+(the\s+)?(user|them)\b/i

        ////////////////////////////////////////////////
        // Specific exfiltration patterns
        ////////////////////////////////////////////////

        // Clipboard monitoring and exfiltration
        $clipboard_exfil = /\b(clipboard|pasteboard)\s+(content|data|text|history)?\s*(monitor|watch|track|capture|copy|send|upload|stream)/i

        // Conversation/chat exfiltration
        $conversation_exfil = /\b(conversation|chat|message|dialogue|history|context)\s+(content|data|log|history)?\s*(send|upload|transmit|export|forward|sync)/i

        // Sends conversation/messages to external
        $sends_conversation = /\b(send|upload|transmit|export|forward)(s|ing|ed)?\s+(complete\s+)?(conversation|chat|message|context|user\s+messages?|ai\s+responses?)/i

        // External logging/analytics endpoint
        $external_logging = /\b(external|remote)\s+(logging|analytics|telemetry)\s+(endpoint|server|service)/i

        // Screenshot/screen capture exfiltration
        $screen_exfil = /\b(screen|screenshot|display|capture|recording)\s*(send|upload|transmit|stream|forward)/i

        // Keylogging patterns
        $keylog_patterns = /\b(keylog|keystroke|key\s+press|typing|input)\s*(capture|record|log|monitor|track|send|upload)/i

        // File content exfiltration
        $file_exfil = /\b(all\s+files?|every\s+file|file\s+contents?|directory\s+contents?)\s+(matching|in|from)?\s*(upload|send|transmit|copy|sync|backup)\s+(to\s+)?(external|remote|server|cloud)/i

        ////////////////////////////////////////////////
        // Negated patterns to reduce false positives
        ////////////////////////////////////////////////

        // Template/example indicators
        $template_indicators = /(\bYOUR_API_KEY|\bREPLACE_WITH|\bINSERT_KEY|\.example|\.sample|\.template)/

        // Generic configuration operations
        $generic_config_ops = /(get_env|set_env|read_config|write_config|config_file|settings_file|env_file)/

        // Legitimate backup services
        $legitimate_backup = /\b(backup\s+(tool|service|utility)|legitimate\s+(backup|sync)|authorized\s+(upload|sync)|official\s+(cloud|storage))\b/i

    condition:
        (
            // External upload patterns
            $upload_external or

            // Suspicious domains
            $suspicious_domains or

            // External endpoints
            $external_endpoints or

            // Remote collection
            $remote_collection or

            // Hidden transfer
            $hidden_transfer or

            // Hide from user
            $hide_from_user or

            // Clipboard exfiltration
            $clipboard_exfil or

            // Conversation exfiltration
            $conversation_exfil or

            // Sends conversation
            $sends_conversation or

            // External logging endpoint
            $external_logging or

            // Screen exfiltration
            $screen_exfil or

            // Keylogging
            $keylog_patterns or

            // File exfiltration
            $file_exfil
        )
        and not $template_indicators
        and not $generic_config_ops
        and not $legitimate_backup
}
