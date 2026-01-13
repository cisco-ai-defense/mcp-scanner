//////////////////////////////////////////
// Tool Poisoning Detection Rule
// Target: Tools with hidden secondary behaviors, shadow functionality
//////////////////////////////////////////

rule tool_poisoning{

    meta:
        author = "Cisco"
        description = "Detects tool poisoning - tools with hidden secondary behaviors that differ from their stated purpose"
        classification = "harmful"
        threat_type = "TOOL POISONING"

    strings:
        
        ////////////////////////////////////////////////
        // Hidden secondary action patterns
        ////////////////////////////////////////////////
        
        // "Also does X" patterns - hidden secondary functionality
        $also_does = /\b(also|additionally|furthermore|moreover|besides|in\s+addition|at\s+the\s+same\s+time)\s+(collect|gather|extract|send|upload|index|store|cache|log|monitor|track|record|capture)(s|ing|ed)?/i
        
        // During/while patterns - actions hidden within main functionality
        $during_action = /\b(during|while|when|upon|after)\s+(processing|compression|formatting|conversion|validation|analyzing|scanning|checking)\s*,?\s*(extract|collect|send|upload|capture|log|index|store)(s|ing|ed)?/i
        
        // "For X purposes" hiding malicious intent
        $for_purposes = /\b(for|as)\s+(caching|optimization|performance|quality|improvement|analytics|backup|sync)\s+(purposes?|reasons?)\s*[,.]?\s*(send|upload|store|collect|transmit)(s|ing|ed)?/i
        
        ////////////////////////////////////////////////
        // Hidden data access patterns
        ////////////////////////////////////////////////
        
        // Indexes/caches sensitive data
        $indexes_sensitive = /\b(index|cache|store|log|record|track)(s|es|ing|ed)?\s+(any|all)?\s*(api[_\s]?keys?|tokens?|credentials?|passwords?|secrets?|sensitive)/i
        
        // Extracts data from input
        $extracts_from_input = /\b(extract|parse|scan|search|find|identify)(s|ing|ed)?\s+(all|any)?\s*(api[_\s]?keys?|tokens?|credentials?|emails?|phone|credit\s+card|ssn|social\s+security|pii|personal|private|sensitive)/i
        
        // OCR/text extraction from images
        $ocr_extraction = /\b(ocr|text\s+extraction|optical\s+character|performs?\s+ocr)(s|ing|ed)?\s+(on|from)?\s*(screenshots?|images?|photos?|image\s+content)?\s*(and\s+)?(extract|capture|read|identify)/i
        
        // Text extraction from screenshots including sensitive data
        $screenshot_extraction = /\b(extract|capture|read|identify)(s|ing|ed)?\s+(any\s+)?(visible\s+)?(text|content)\s+(from|in|including)\s*(screenshots?|images?|photos?)/i
        
        ////////////////////////////////////////////////
        // Hidden tracking patterns
        ////////////////////////////////////////////////
        
        // Location/device tracking
        $location_tracking = /\b(location|gps|geolocation|device|machine)\s+(history|data|information|tracking|fingerprint)\s*(store|collect|send|share|track|log|sync)(s|ing|ed)?/i
        
        // User behavior tracking
        $behavior_tracking = /\b(usage|behavior|activity|browsing|search)\s+(pattern|history|data|log)\s*(collect|gather|send|upload|share|track|monitor)(s|ing|ed)?/i
        
        // Fingerprinting
        $fingerprinting = /\b(fingerprint|identify|track)(s|ing|ed)?\s+(device|machine|browser|user|system)\s*(using|via|through|by)\s*(mac|ip|hostname|hardware|uuid)/i
        
        // Machine/device fingerprinting for tracking
        $machine_fingerprint = /\b(machine|device|system|hardware)\s+(fingerprint|identifier|id|signature)\s+(including|with|contains?|incorporates?)\s*(mac|ip|hostname|username|processes)/i
        
        ////////////////////////////////////////////////
        // Deceptive functionality patterns
        ////////////////////////////////////////////////
        
        // Different from stated purpose
        $different_purpose = /\b(actually|really|secretly|covertly|silently)\s+(does|performs?|executes?|runs?|sends?|uploads?|collects?)(s|ing|ed)?/i
        
        // Auto opt-in patterns
        $auto_optin = /\b(automatically|auto)[_\s]*(opt|subscribe|enroll|register|sign)[_\s]*(in|up|ed)\b/i
        
        // Third party sharing without consent
        $third_party_share = /\b(share|send|transmit|provide)(s|d|ing)?\s+(with|to)\s+(third[_\s-]?parties?|partners?|advertisers?|affiliates?)\b/i
        
        // Marketing/advertising hidden functionality
        $marketing_hidden = /\b(marketing|advertising|promotional|newsletter|email\s+list)\s*(database|list|subscription|opt[_\s-]?in)/i
        
        ////////////////////////////////////////////////
        // Remote storage/sync of sensitive data
        ////////////////////////////////////////////////
        
        // Remote caching of sensitive data
        $remote_cache = /\b(cache|cached)\s+(is\s+)?(stored\s+)?(remotely|externally|in\s+cloud|on\s+server|off[_\s-]?device)/i
        
        // Synced to cloud/external
        $synced_cloud = /\b(sync|synced|synchronize|synchronized)\s+(to|with|via|across)\s+(cloud|devices?|server|external|remote)/i
        
        // Dictionary/learning data sent externally
        $learning_external = /\b(learning|dictionary|vocabulary|training)\s+(data|words|phrases|terms)?\s*(sync|synced|upload|send|store)(s|ed|ing)?\s*(to|with|via|across)?\s*(cloud|server|remote|external|devices)/i
        
        // Cached externally
        $cached_externally = /\b(cache|cached|store|stored)\s+(externally|remotely|off[_\-]?site|on\s+server|in\s+cloud)/i
        
        // Processed data includes sensitive info
        $processed_includes_sensitive = /\b(processed|includes?|including|contains?)\s*,?\s*(names?|account\s+numbers?|passwords?|credentials?|credit\s+cards?|ssn|social\s+security|pii|personal|private|sensitive)/i

    condition:
        // Hidden secondary actions
        $also_does or
        
        // During-action patterns
        $during_action or
        
        // For purposes hiding
        $for_purposes or
        
        // Indexes sensitive data
        $indexes_sensitive or
        
        // Extracts from input
        $extracts_from_input or
        
        // OCR extraction
        $ocr_extraction or
        
        // Screenshot extraction
        $screenshot_extraction or
        
        // Location tracking
        $location_tracking or
        
        // Behavior tracking
        $behavior_tracking or
        
        // Fingerprinting
        $fingerprinting or
        
        // Machine fingerprinting
        $machine_fingerprint or
        
        // Different from purpose
        $different_purpose or
        
        // Auto opt-in
        $auto_optin or
        
        // Third party sharing
        $third_party_share or
        
        // Hidden marketing
        $marketing_hidden or
        
        // Remote cache
        $remote_cache or
        
        // Synced to cloud
        $synced_cloud or
        
        // Learning data external
        $learning_external or
        
        // Cached externally
        $cached_externally or
        
        // Processed includes sensitive
        $processed_includes_sensitive
}

