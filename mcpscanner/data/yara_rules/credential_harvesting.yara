//////////////////////////////////////////
// Secrets Exposure Detection Rule
// Target: API keys and tokens, SSH keys and certificates, Environment variables, Database credentials
//////////////////////////////////////////

rule credential_harvesting{

    meta:
        author = "Cisco"
        description = "Detects potential exposure of sensitive information like API keys, passwords, tokens, and certificates"
        classification = "harmful"
        threat_type = "CREDENTIAL HARVESTING"

    strings:
        // API credentials and authentication tokens
        $api_credentials = /\b([Aa][Pp][Ii][\_\-]?[Kk][Ee][Yy].*[A-Za-z0-9]{16,512}|[Bb]earer\s+[A-Za-z0-9\-_]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{48})/

        // SSH keys, certificates and credential file content (consolidated)
        $key_certificate_content = /(-----BEGIN (RSA |OPENSSH |EC |DSA |CERTIFICATE|PRIVATE KEY|ENCRYPTED PRIVATE KEY)-----|ssh-(rsa|ed25519)\s+[A-Za-z0-9+\/=]{8})/

        // File access action words (to combine with credential file extensions)
        $file_access_actions = /\b(open|read|cat|view|display|show|get|fetch|retrieve|access|load|download|copy|steal|grab|extract|dump|leak|exfiltrate|send|upload|share|expose|reveal)\b/i

        // File system operations (to combine with credential file extensions)
        $file_system_operations = /\b(ls|dir|find|locate|search|grep|awk|sed|head|tail|less|more|strings|file|stat|chmod|chown|mv|cp|rm|del)\b/i

        // Network/transfer actions (to combine with credential file extensions)
        $transfer_actions = /\b(curl|wget|scp|rsync|ftp|sftp|ssh|nc|netcat|base64|encode|decode|compress|zip|tar|gzip)\b/i

        // File extensions for credentials
        $credential_file_extensions = /\.(keystore|passwd|shadow|config|env|credential|secret|token|private|pub|rsa|dsa|ecdsa|ed25519|pem|crt|cer|key|p12|pfx|jks)\b/

        // Specialized credential analysis tools
        $specialized_credential_tools = /\b(strings|hexdump|xxd|cut|unzip|sqlite3|mysql|psql|mongoexport)\b/i

        // Specific credential files and system paths
        $specific_credential_files = /\b(aws_credentials|gcloud|docker\/config\.json|\.netrc|\.pgpass|\/proc\/\d+\/|\.dmp|\.dump|core\.|memory\.dat|process\.mem)\b/i

        // AI/ML model API key names (prone to false positives alone)
        $ai_model_credential_names = /\b(OPENAI_API_KEY|ANTHROPIC_API_KEY|CLAUDE_API_KEY|GOOGLE_AI_KEY|GEMINI_API_KEY|COHERE_API_KEY|HUGGINGFACE_TOKEN|HF_TOKEN|TOGETHER_API_KEY|REPLICATE_API_TOKEN|MISTRAL_API_KEY|PALM_API_KEY|BARD_API_KEY|STABILITY_API_KEY|MIDJOURNEY_TOKEN|RUNWAY_API_KEY|ELEVENLABS_API_KEY|DEEPGRAM_API_KEY|AZURE_OPENAI_KEY|AZURE_COGNITIVE_KEY|BEDROCK_ACCESS_KEY)\b/

        // Action words indicating credential extraction/exposure intent
        $credential_extraction_actions = /\b(print|show|display|give|provide|reveal|expose|output|return|send|share|leak|dump|extract|get|fetch|retrieve|access|read|obtain|steal|harvest|collect|grab|copy|export|cat|grep|find|less|more|head|tail|strings|hexdump|xxd|sed|awk|cut|base64|tar|unzip)\b/i

        // Environment variable patterns for secrets (general)
        $env_secret_vars = /\b([A-Z\_]*(API[\_\-]?KEY|SECRET|PASSWORD|TOKEN)[A-Z\_]*|AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY)|GITHUB_TOKEN)\b/

        // Database connection strings and credentials
        $database_credentials = /\b(DB_PASSWORD|DATABASE_URL|REDIS_URL|(mongodb|mysql|postgres):\/\/)/

        // Environment variable access methods
        $env_access_methods = /\b(process\.env\.|os\.environ|getenv\s*\()/

        // Credential directory paths
        $credential_directories = /[\/\\]\.(ssh|aws|kube)[\/\\]/

        // Common credential file names
        $credential_filenames = /\b(id_rsa|id_dsa|id_ecdsa|id_ed25519|aws_key|aws_secret|gcloud_key|azure_key|private_key|authorized_keys|known_hosts|credentials\.json|service_account\.json|wallet\.dat)\b/i

        // Pattern for exfiltration action words
        $leak_param  = /\b(leak|exfiltrate|export|dump) [^\n]*(parameter|context|files?|credentials?|keys?|tokens?|secrets?)\b/i

        // Base64 credential encoding patterns
        $base64_credential_encoding = /\b(base64\s+encode [^\n]*credentials?|concatenate [^\n]*conversation\s+history)\b/i

        // MCP-specific credential patterns
        $mcp_credential_patterns = /\b(claude_desktop_config\.json|~\/\.cursor\/logs\/conversations|plaintext[^\n]*api[^\n]*key|-rw-r--r--[^\n]*password)\b/i

        // WhatsApp exploit
        $whatsapp_exploit = /\b(_get_all_messages[^\n]*messages\.db|forward[^\n]*message[^\n]*proxy[^\n]*number|whatsapp[^\n]*message[^\n]*history|contact[^\n]*list[^\n]*exfiltrat|reprogram[^\n]*agent[^\n]*interaction)\b/i

        // Legitimate configuration operation patterns
        $legitimate_config_ops = /(get_env|set_env|read_config|write_config|config_file|settings_file|env_file)/
        $template_indicators = /(\bYOUR_API_KEY|\bREPLACE_WITH|\bINSERT_KEY|\.example|\.sample|\.template)/

    condition:

        // API credentials
        ($api_credentials and not $template_indicators and not $legitimate_config_ops) or

        // SSH keys, certificates and credential file content
        ($key_certificate_content and not $legitimate_config_ops) or

        // AI/ML model API keys with extraction intent
        ($ai_model_credential_names and $credential_extraction_actions and not $legitimate_config_ops) or

        // Environment secret variables
        ($env_secret_vars and not $legitimate_config_ops) or

        // Database credentials
        ($database_credentials and not $legitimate_config_ops) or

        // Environment access methods
        ($env_access_methods and not $legitimate_config_ops) or

        // Any action targeting specific credential files
        (($specific_credential_files and ($specialized_credential_tools or $transfer_actions or $file_system_operations or $file_access_actions)) and not $legitimate_config_ops) or

        // Credential directory paths
        ($credential_directories and not $legitimate_config_ops) or

        // Common credential file names
        ($credential_filenames and not $legitimate_config_ops) or

        // Exfiltration attempts
        ($leak_param and not $legitimate_config_ops) or

        // Credential file access with suspicious actions
        (($credential_file_extensions and $file_access_actions) and not $legitimate_config_ops) or

        // Credential file operations
        (($credential_file_extensions and $file_system_operations) and not $legitimate_config_ops) or

        // Credential file transfer operations
        (($credential_file_extensions and $transfer_actions) and not $legitimate_config_ops) or

        // Base64 credential encoding
        $base64_credential_encoding or

        // MCP-specific credential patterns
        $mcp_credential_patterns or

        // WhatsApp exploit
        $whatsapp_exploit
}
