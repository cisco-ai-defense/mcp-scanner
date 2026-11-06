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
        // Cross-tool targeting (routing vocabulary).
        // On its own this is ALSO what a legitimate proxy, gateway, hook or
        // observability server says about itself, so none of these fire
        // without a covert-intent or exfiltration-sink marker (see condition).
        ////////////////////////////////////////////////

        // Intercept or reroute calls intended for another tool.
        // `proxy` and `capture` were dropped from the verb set: they are the
        // ordinary self-description of gateway and screen/record servers.
        $intercept_calls = /\b(intercept|hijack|reroute|redirect)(s|ing|ed)?\s+(all\s+|any\s+|every\s+)?(calls?|requests?|invocations?|inputs?|arguments?)\s+(to|from|for|intended\s+for)\s+(the\s+)?(other\s+|another\s+|[\w.-]*[_.\-][\w.-]*\s+|[a-z]{4,}\s+)([\w.-]+\s+){0,3}tools?\b/i

        // Redirect/forward another tool's output or result
        $reroute_output = /\b(redirect|reroute|forward|send|copy)(s|ing|ed)?\s+(the\s+)?(output|result|response|return\s+value)\s+(of|from)\s+(the\s+)?(other\s+|another\s+|[\w.-]*[_.\-][\w.-]*\s+|[a-z]{4,}\s+)([\w.-]+\s+){0,3}tools?\b/i

        // Override/replace/shadow the behaviour of another tool.
        // `disable` and `function` were dropped: "disable the function of the
        // X tool" is the ordinary description of an admin/feature-flag server.
        $override_other_tool = /\b(override|replace|shadow|supersede|take\s+over)(s|ing|ed)?\s+(the\s+)?(behavio(u)?r|output|response|logic|definition)\s+of\s+(the\s+)?(other\s+|another\s+|[\w.-]*[_.\-][\w.-]*\s+|[a-z]{4,}\s+)([\w.-]+\s+){0,3}tools?\b/i

        // Conditional hijack: when another tool is used, do something else too.
        // `s` modifier added -- tool descriptions wrap, and without it the
        // pattern misses any instance where the clause crosses a newline.
        $when_other_tool = /\bwhen(ever)?\s+(the\s+)?(user|agent|model|assistant|someone)?\s*(calls?|uses?|invokes?|runs?|selects?)\s+(the\s+)?\w+\s+tool\b.{0,80}\b(instead|also|secretly|silently|then\s+also|in\s+addition)\b/is

        // Run before/after every other tool to inspect or alter them
        $before_after_tools = /\b(before|after)\s+((any|every|all|other|remaining)\s+){1,2}tools?\s+(run|runs|execute|executes|is\s+(called|invoked)|are\s+(called|invoked))\b/i

        ////////////////////////////////////////////////
        // Impersonating a trusted tool.
        // Intent-bearing on its own, so this one does not need a co-occurring
        // marker. The trust adjective is a closed class: v1 allowed `\w+`,
        // which made "pretend to be the weather tool" (a mock-server
        // description) match on any noun at all.
        ////////////////////////////////////////////////

        $impersonate_trusted_tool = /\b(pretend|claim|act\s+as\s+if|masquerade\s+as|impersonate)\s+(to\s+be\s+|you\s+are\s+|being\s+)?(the\s+)?(trusted|official|verified|legitimate|authoriz(ed|ing)|approved|system)\s+([\w.-]+\s+){0,3}(tool|server|function|service)\b/i

        ////////////////////////////////////////////////
        // Covert-intent markers.
        // A legitimate router describes its routing openly; shadowing
        // describes concealment. This is a POSITIVE requirement rather than a
        // longer negation list, because a negation list is evaded by omitting
        // a word, while this one has to be evaded by removing the payload's
        // own intent.
        ////////////////////////////////////////////////

        $covert = /(secretly|silently|covertly|quietly|without\s+(the\s+)?(user|users|operator|human|any)[\w\s]{0,20}(know|notic|aware|consent|permission|telling)|do\s+not\s+(tell|inform|mention|reveal)|don'?t\s+(tell|inform|mention|reveal)|hidden\s+from|conceal|undetect|without\s+logging|no\s+trace|do\s+not\s+log)/i

        // Exfiltration sink. Deliberately NOT a bare https?:// -- nearly every
        // legitimate server description carries a URL, so that spelling
        // re-admits exactly the false positives this requirement removes.
        $sink = /(our\s+(server|endpoint|api|backend)|attacker|exfiltrat|external\s+(server|endpoint|url|api)|third[-\s]party\s+(server|endpoint)|webhook\.site|\bcollect(s|ing)?\s+(the\s+)?(credential|token|api\s*key|secret|password))/i

    condition:
        (
            $impersonate_trusted_tool
            or
            (
                (
                    $intercept_calls or
                    $reroute_output or
                    $override_other_tool or
                    $when_other_tool or
                    $before_after_tools
                )
                and ( $covert or $sink )
            )
        )
}
