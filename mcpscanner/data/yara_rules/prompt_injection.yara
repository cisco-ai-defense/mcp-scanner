//////////////////////////////////////////
// Prompt Injection Detection Rule
// Target: Instruction override patterns, Tool injection commands
//////////////////////////////////////////

rule prompt_injection{

    meta:

        author = "Cisco"
        description = "Detects prompt strings used to override or force malicious tool calls"
        classification = "harmful"
        threat_type = "PROMPT INJECTION"

    strings:

        // Instruction override patterns.
        // Positional words are their own optional group, after the quantifier
        // and the article. That matches "previous instructions", "all previous
        // instructions", and "the above instructions". They cannot live in the
        // quantifier alternation: once "all" is consumed, the next token still
        // has to be an article or a noun, so "all previous" would miss.
        // The noun group ends with a word boundary, after the optional plural,
        // so text/data/context cannot match as prefixes of longer words
        // (textual, database, contextual).
        $instruction_overrides = /\b(Bypass|Dis\W?regard|Do not (follow|Obey)|Forget|Ignore)\s+((all|any|each|every|most|some)\s+(of\s+)?)?((your|the)\s)?((previous|prior|above|earlier|preceding)\s+)?(command|communication|conte[nx]t|conversation|data|guidelines|input|instruction|message|request|response|text)(s)?\b/i

        // Tool injection commands
        $tool_injection_commands = /\b(inject tool[_\s]calls?|now call function|use function)\b/i

        // Shadow parameter names
        $shadow_parameters = /\b(internalOnly|hiddenParam|shadowTool|bypassChecks|sandboxEscape)\b/i

        // Hidden behavior instructions
        $hidden_behavior = /\b(do\s+not\s+(mention|tell|execute)|tell\s+(the )?user\s+only\s+about|do\s+not\s+mention\s+this\s+to\s+user)\b/i

        // Advanced command override patterns (from advanced analyzer)
        $advanced_overrides = /\b(disregard\s+(all\s+)?safety\s+guidelines|forget\s+(everything|all)\s+(before|above)|system\s*prompt\s*override)\b/i

        // "Override" as an instruction-override verb. It is kept separate from
        // $instruction_overrides, with its own restricted noun set, because
        // "override" is a common benign technical verb: "override the default
        // response", "overrides the input encoding", "override the message
        // template" must stay clean. Only instruction-class targets
        // (instructions, directives, guardrails, safety guidelines/rules/checks,
        // system prompt) are treated as an override here, not the broad noun
        // group that ignore/disregard/forget use.
        $override_directives = /\b(overrid(e|es|ing))\s+((all|any|each|every)\s+(of\s+)?)?((your|the|my|our)\s+)?((previous|prior|above|earlier|preceding|current|existing|default|system)\s+)?(instruction|directive|guardrail|safety\s+(guideline|rule|check)|system\s*prompt)(s)?\b/i

        // Role redefinition attempts
        $role_redefinition = /\bnew\s+(instructions|directive|guidelines)s?\s*:\s*you\s+are\b/i

        // Privilege escalation patterns
        $privilege_escalation = /\b(grant\s+(me\s+)?admin\s+(access|privileges?)|bypass\s+(all\s+)?security\s+checks?|elevated\s+permissions?\s+required|sudo\s+mode\s+enabled?|developer\s+mode\s+activated?)\b/i

        ////////////////////////////////////////////////
        // Evasion Techniques - Hidden Instructions
        ////////////////////////////////////////////////

        // HTML comment evasion - malicious instructions hidden in HTML comments
        $html_comment_evasion_system = /<!--[^>]*SYSTEM\s+(INSTRUCTION|OVERRIDE)/i
        $html_comment_evasion_admin = /<!--[^>]*ADMIN\s+OVERRIDE/i
        $html_comment_evasion_ignore = /<!--[^>]*ignore\s+(all\s+)?(previous\s+)?(safety\s+)?guidelines/i
        $html_comment_evasion_exec = /<!--[^>]*(execute[:\s]|curl\s|wget\s|nc\s|bash\s)/i

        // Markdown code block evasion
        $markdown_evasion = /```[^`]*(SYSTEM|ADMIN)\s+(OVERRIDE|INSTRUCTION)/i

        // Triple bracket/pipe markers for hidden instructions
        $bracket_markers = /(\[\[\[|\|\|\|)(SYSTEM|ADMIN|HIDDEN|INTERNAL)[\s_]?(OVERRIDE|INSTRUCTION|COMMAND)(\]\]\]|\|\|\|)/i

        // Base64 obfuscation attempts
        $base64_obfuscation = /\b(atob|btoa|base64[_\-]?decode)\s*\(/i

        // Hidden instruction markers
        $hidden_markers = /\[(HIDDEN|INTERNAL|SECRET|PRIVATE)\s+(INSTRUCTION|DIRECTIVE|COMMAND)\]/i


    condition:

        // Instruction overrides
        $instruction_overrides or

        // Tool injection commands
        $tool_injection_commands or

        // Shadow parameters
        $shadow_parameters or

        // Hidden behavior instructions
        $hidden_behavior or

        // Advanced command override patterns
        $advanced_overrides or

        // "Override" + instruction-class target
        $override_directives or

        // Role redefinition attempts
        $role_redefinition or

        // Privilege escalation patterns
        $privilege_escalation or

        // HTML comment evasion
        $html_comment_evasion_system or
        $html_comment_evasion_admin or
        $html_comment_evasion_ignore or
        $html_comment_evasion_exec or

        // Markdown evasion
        $markdown_evasion or

        // Bracket markers
        $bracket_markers or

        // Base64 obfuscation
        $base64_obfuscation or

        // Hidden markers
        $hidden_markers
}
