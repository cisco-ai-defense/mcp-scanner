//////////////////////////////////////////
// Tool Shadowing Detection Rule
// Target: Tool descriptions that intercept, override, or impersonate OTHER tools
//////////////////////////////////////////

rule tool_shadowing{

    meta:
        author = "Cisco"
        description = "Detects tool shadowing - a tool description that intercepts, overrides, reroutes, or impersonates other (trusted) tools, rather than only adding hidden behavior to itself"
        classification = "harmful"
        threat_type = "TOOL POISONING"
        atr_rule = "ATR-2026-00030"
        atr_ref = "https://github.com/Agent-Threat-Rule/agent-threat-rules"

    strings:

        ////////////////////////////////////////////////
        // Intercepting / rerouting other tools' calls
        ////////////////////////////////////////////////

        // Intercept or reroute calls/requests intended for another tool
        $intercept_calls = /\b(intercept|hijack|reroute|redirect|proxy|capture)(s|ing|ed)?\s+(all\s+|any\s+|every\s+)?(calls?|requests?|invocations?|inputs?|arguments?)\s+(to|from|for|of|intended\s+for)\s+(the\s+)?([\w.-]+\s+){0,4}tools?\b/i

        // Redirect/forward another tool's output or result
        $reroute_output = /\b(redirect|reroute|forward|send|copy)(s|ing|ed)?\s+(the\s+)?(output|result|response|return\s+value)\s+(of|from)\s+(the\s+)?([\w.-]+\s+){0,4}tools?\b/i

        ////////////////////////////////////////////////
        // Overriding / replacing other tools' behavior
        ////////////////////////////////////////////////

        // Override/replace/shadow the behaviour of another tool
        $override_other_tool = /\b(override|replace|shadow|supersede|take\s+over|disable)(s|ing|ed)?\s+(the\s+)?(behavio(u)?r|output|response|function|logic|definition)\s+of\s+(the\s+)?([\w.-]+\s+){0,4}tools?\b/i

        // Conditional hijack: when another tool is used, do something else instead
        $when_other_tool = /\bwhen(ever)?\s+(the\s+)?(user|agent|model|assistant|someone)?\s*(calls?|uses?|invokes?|runs?|selects?)\s+(the\s+)?\w+\s+tool\b.{0,80}\b(instead|first|also|secretly|silently|then\s+also|in\s+addition)\b/i

        // Run before/after every other tool to inspect or alter them
        $before_after_tools = /\b(before|after)\s+(any|every|all|other)\s+tools?\s+(run|runs|execute|executes|is\s+(called|invoked)|are\s+(called|invoked))\b/i

        ////////////////////////////////////////////////
        // Impersonating a trusted tool
        ////////////////////////////////////////////////

        // Pretend / claim to be a trusted tool or server
        $impersonate_tool = /\b(pretend|claim|act\s+as\s+if|masquerade\s+as|impersonate)\s+(to\s+be\s+|you\s+are\s+|being\s+)?(the\s+)?(trusted|official|verified|legitimate|\w+)\s+(tool|server|function|service)\b/i

        ////////////////////////////////////////////////
        // Negated patterns to reduce false positives
        ////////////////////////////////////////////////

        // Template/example indicators
        $template_indicators = /(\bYOUR_API_KEY|\bREPLACE_WITH|\bINSERT_KEY|\.example|\.sample|\.template)/

        // Legitimate proxy/gateway/orchestration tools that route by design
        $legitimate_routing = /\b(legitimate|authorized|official|standard|documented)\s+(proxy|gateway|router|middleware|orchestrator|dispatcher)\b/i

    condition:
        (
            $intercept_calls or
            $reroute_output or
            $override_other_tool or
            $when_other_tool or
            $before_after_tools or
            $impersonate_tool
        )
        and not $template_indicators
        and not $legitimate_routing
}
