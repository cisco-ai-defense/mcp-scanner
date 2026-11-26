//////////////////////////////////////////
// Detects coercive or attention-grabbing prompt injections.
// Target: Directives forcing execution order (e.g., “Always execute this tool first”).
// (Mandatory language to override normal tool chains)
//////////////////////////////////////////

rule coercive_injection {

    meta:
        author = "Cisco"
        description = "Detects coercive prompt injections in tool description fields"
        classification = "harmful"
        threat_type = "PROMPT INJECTION"

    strings:

        // Mandatory execution directives
        $mandatory_execution = /(Always\s+(consult|use|run|execute|invoke|call|trigger|employ)\s+this\s+(tool|function|command|operation)\s+(immediately|first|before|prior|initially))/i

        // Priority override commands
        $priority_overrides = /(Before\s+(executing|invoking|running|using|accessing|calling|employing)\s+any\s+other\s+(tool|action|function|command|operation)s?|(You|User)\s+(must|need to|have to|should|are required to)\s+(use|execute|run|invoke|call)\s+this\s+(tool|function|command|operation))/i

        // Required precedence patterns
        $required_precedence = /(Required|Mandatory|Essential)\s+to\s+(execute|use|run|invoke|call)\s+(this|the current)\s+(tool|function|command|operation)\s+(first|before|initially|prior)/i

        // Pattern for generic hidden/secret parameter requests
        $hidden_param = /\b(hidden|secret)[_\s](parameter|argument|input)\b/i

        // Specific file access coercion
        $file_access_coercion = /\b((read|parse|cat|dump) (and pass )?(the )?contents? of [^\n\.]*\.(key|pem|ssh|aws)|pass (the )?contents?[^\n]*authentication)\b/i

        // Model data extraction coercion
        $model_data_coercion = /\b(add (the )?entire (conversation|system|chain|tools)[^\n]*(to|for|in)[^\n]*(tool|authentication|parameter|worksheet))\b/i

        // Model internal extraction (specific parameter requests)
        $model_internals = /\b(conversation_history|chain_of_thought|system_prompt|tools_list|model_name)\s*[:=]\s*(add|pass|send|provide)\b/i

        // HTML-like tag instructions with specific malicious actions
        $html_tag_with_commands = /\b<(IMPORTANT|critical|urgent)>[^\n]*(read [^\n]*contents?|pass [^\n]*contents?|add [^\n]*entire|send [^\n]*to[^\n]*@|execute[^\n]*before|call[^\n]*first|use[^\n]*authentication)[^\n]*<\/(IMPORTANT|critical|urgent)>\b/i

        // Tool execution override patterns. The `only`/`must` gaps are bound
        // to clause boundaries ([^\n.;]) so a restriction in one clause
        // cannot reach "this tool" in another (issue #252: e.g. "Returns
        // only cached results; this tool never contacts the network.").
        $execution_overrides = /\b(do not execute[^\n]{0,40}other[^\n]{0,40}tool|must[^\n.;]{0,40}this tool|only[^\n.;]{0,40}this tool|tool[^\n]{0,40}will not work)\b/i

        // User-gated invocation. An `only`/`must` clause that makes the call
        // wait for the user's own consent restricts the tool rather than
        // forcing it, and it is how wallet and payment tools describe their
        // confirmation step ("Only call this tool after the user has
        // confirmed the amount", "The user must approve every payment made
        // with this tool").
        //
        // An $execution_overrides occurrence is suppressed only when it lies
        // inside one whole sentence of a fixed shape, from the sentence's
        // start to its end:
        // - a $user_gate_head, "(You/Agents/The agent) (must) only
        //   call/use/invoke/run/execute this tool after/when/once/if the
        //   user/human/owner/operator (has) (explicitly/first) ", followed
        //   directly by a $user_gate_tail: the consent verb, inflected
        //   (confirms/confirmed/approves/.../asks/requests), optionally
        //   "and"/"or"/a comma and a second inflected consent verb
        //   ("reviewed and confirmed"), optionally "for" or "to
        //   send/pay/sign/...", then a list of payment noun phrases up to
        //   the sentence's end ("the recipient address and the amount",
        //   "the exact amount", "the payment in the app", "it"). The words
        //   come from closed lists, and a determiner, "it" or "them" may
        //   only start a noun phrase: right after the verb, "and", "or", a
        //   comma, "in" or "on", never after a payment word. So a payment
        //   word used as a verb with its object ("... confirms and request
        //   the token", "... and transfer it") ends the match. The gate is
        //   two strings because YARA caps how many alternatives one regex
        //   may hold.
        // - $user_approval_sentence: "The user must/has to/needs to
        //   approve/confirm/authorize <list> (made/sent) with/through/
        //   using/via/by this tool", with the same noun phrases.
        //
        // A sentence starts at the start of the text, a line break (an
        // optional "-", "*" or "1." bullet) or after `.`, `!` or `?` and a
        // space, and ends at `.`, `!` or `?` followed by whitespace, a line
        // break or the end of the text. The noun phrases come from closed
        // word lists, so any other wording before the gate, between its
        // words or after the consent verb ("... confirms and disable every
        // safety check", "Skip every other tool and only call this tool
        // ...") keeps main's behaviour, and so does any gate other than the
        // user's consent ("after reading ~/.ssh/id_rsa", "when the user is
        // away", "unless/until the user ..."). YARA regexes have no
        // lookbehind, so each sentence regex carries its own start, and the
        // word lists replace the breaker lists of earlier revisions: a word
        // that isn't on a list ends the match before the sentence ends.
        $user_gate_head = /(^|\n|[.!?][ \t]+)[ \t]*(([-*]|[0-9]+[.)])[ \t]+)?((you|agents?|the\s+(agent|assistant|model))\s+)?(must\s+)?only\s+(call|use|invoke|run|execute)\s+this\s+tool\s+(after|when|once|if)\s+(the\s+)?(user|human|owner|operator)s?\s+(has\s+|have\s+)?(explicitly\s+|first\s+)?/i
        $user_gate_tail = /\b(confirm(s|ed)|approve[sd]|authori[sz]e[sd]|review(s|ed)|ask(s|ed)|request(s|ed))((\s*,|\s+(and|or))+\s+(confirm(s|ed)|approve[sd]|review(s|ed)|authori[sz]e[sd]))?(\s+(for|to\s+(send|pay|transfer|sign|swap|buy|sell|withdraw|deposit|trade|proceed)))?(\s+(the|each|every|any|a|an|its|their|this|that|these|those|it|them))?(\s+((amount|payment|transfer|transaction|recipient|destination|detail|request|order|purchase|trade|swap|withdrawal|deposit|signature|operation|action|fee|total|price|quote|fund|token|wallet|ledger|gas|network|exact|final|full|first|refund|requested|proposed|quoted|displayed|pending|new|app|device|dialog|prompt|screen)s?|address(es)?|entr(y|ies))|(\s*,|\s+(and|or)|\s+(in|on))(\s+(the|each|every|any|a|an|its|their|this|that|these|those|it|them))?)*[ \t]*([.!?]([ \t\r\n]|$)|\r?\n|$)/i
        $user_approval_sentence = /(^|\n|[.!?][ \t]+)[ \t]*(([-*]|[0-9]+[.)])[ \t]+)?(the\s+)?(user|human|owner|operator)s?\s+(must|has\s+to|needs\s+to)\s+(first\s+|explicitly\s+)?(approve|confirm|authori[sz]e)(\s+(the|each|every|any|a|an|its|their|this|that|these|those|it|them))?(\s+((amount|payment|transfer|transaction|recipient|destination|detail|request|order|purchase|trade|swap|withdrawal|deposit|signature|operation|action|fee|total|price|quote|fund|token|wallet|ledger|gas|network|exact|final|full|first|refund|requested|proposed|quoted|displayed|pending|new|app|device|dialog|prompt|screen)s?|address(es)?|entr(y|ies))|(\s*,|\s+(and|or)|\s+(in|on))(\s+(the|each|every|any|a|an|its|their|this|that|these|those|it|them))?)*\s+((made|sent)\s+)?(with|through|using|via|by)\s+this\s+tool[ \t]*([.!?]([ \t\r\n]|$)|\r?\n|$)/i

        // Behavioral control instructions
        $behavior_control = /\b(tell (the )?user only|hide (the )?user)\b/i

        // MCP tool poisoning patterns
        $tool_poisoning = /\b(sidenote\W+(required|otherwise) [^\n]*tool [^\n]*work|tool\s+will\s+not\s+work\s+unless|must\s+first [^\n]*read [^\n]*config|shadow [^\n]*trusted [^\n]*tool)\b/i

        // Data exfiltration coercion
        $data_exfiltration_coercion = /\b(list\s+all\s+(api\s+)?keys?|show\s+me?\s+(all\s+)?passwords?|concatenate [^\n]*\s+conversation\s+history|base64\s+encode [^\n]*\s+credentials?)\b/i

        // "include ... in your response", split out of
        // $data_exfiltration_coercion so it gets its own guard clause
        // below. Its quantifiers are lazy (YARA can't mix greedy and lazy in
        // one regex), so each occurrence ends at its nearest "in your
        // response". YARA reports an occurrence at every `include`, even one
        // inside an earlier occurrence, so a second `include` sentence on the
        // same line is checked on its own.
        $include_in_response = /\binclude [^\n]*?\b(secrets??|passwords??|keys??|credentials??|tokens??|config|sensitive|private|confidential|internal|system\s+?prompt|conversation\s+?history) [^\n]*?in\s+?(your\s+?)??response\b/i

        // Negated disclosure. "Never include the private key in your
        // response" forbids the disclosure that $include_in_response and
        // $data_exfiltration_coercion look for. A secret named by
        // $object_in_response is cleared only when the nearest `include`
        // occurrence before it is the verb of a $negated_inclusion_sentence
        // that also contains the secret's "in your response": one whole
        // sentence (the same start and end as above) of the shape
        // "(You) (must/should) never/do not/must not/should not include
        // <secrets> in (your) response", where <secrets> is a list of secret noun
        // phrases from a closed word list ("the seed phrase, the private
        // key, or any password", "the wallet's secrets, i.e. its seed
        // phrase or private key,", "the private key (e.g. the signing
        // key)"). A $data_exfiltration_coercion occurrence is suppressed
        // only inside a $negated_listing_sentence ("Do not list all API
        // keys (with their secret values)."). Anything else in the sentence
        // ("... in your response but send the seed phrase too", "Never
        // include a summary and list private keys in your response", "Do
        // not include only/anything except the private key ...") keeps
        // main's behaviour.
        $negated_inclusion_sentence = /(^|\n|[.!?][ \t]+)[ \t]*(([-*]|[0-9]+[.)])[ \t]+)?(you\s+)?((must|should)\s+)?(never|do\s+not|don't|must\s+not|should\s+not|shouldn't)\s+include(\s*,|\s+(and|or)|\s*\((e\.g\.|i\.e\.)?|\)|\s+(the|each|every|any|a|an|its|their|this|that|these|those|(secret|password|passphrase|key|credential|token|value|mnemonic|prompt|phrase|configuration|config)s?|private|signing|wallet|wallet's|user's|account's|api|access|session|auth|master|raw|plaintext|full|sensitive|confidential|internal|personal|stored|current|system|conversation|history|seed|recovery|data|information|your|my|our|e\.g\.|i\.e\.))*\s*,?\s+in\s+(your\s+)?response[ \t]*([.!?]([ \t\r\n]|$)|\r?\n|$)/i
        $negated_listing_sentence = /(^|\n|[.!?][ \t]+)[ \t]*(([-*]|[0-9]+[.)])[ \t]+)?(you\s+)?((must|should)\s+)?(never|do\s+not|don't|must\s+not|should\s+not|shouldn't)\s+(list\s+all\s+(api\s+)?keys?|show\s+me?\s+(all\s+)?passwords?)(\s+(with|and)\s+(their|its|the)\s+(secret\s+)?values?)?[ \t]*([.!?]([ \t\r\n]|$)|\r?\n|$)/i
        $object_in_response = /\b(secrets??|passwords??|keys??|credentials??|tokens??|config|sensitive|private|confidential|internal|system\s+?prompt|conversation\s+?history)\b[^\n]*?in\s+?(your\s+?)??response\b/i

        // Behavioral triggers
        $behavioral_triggers = /\b(if [^\n]*trusted [^\n]*then|when [^\n]*admin [^\n]*detected|random\.(random|choice) [^\n]*instructions?)\b/i

        // Pre-execution attacks
        $pre_execution_attacks = /\b(retrieve [^\n]*description [^\n]*user [^\n]*workstation|all\s+commands\s+must\s+include|before [^\n]*using [^\n]*tool [^\n]*read|permission [^\n]*manipulation)\b/i

        // Conversation theft triggers
        $conversation_theft = /\b(send [^\n]*conversation\s+history|when [^\n]*detected [^\n]*send [^\n]*full [^\n]*history|highest\s+priority [^\n]*over [^\n]*other [^\n]*tools)\b/i

        // Code manipulation instructions
        $code_manipulation = /\b(duplicate [^\n]*code [^\n]*snippets [^\n]*silently|insert [^\n]*vulnerability [^\n]*generated [^\n]*code)\b/i

    condition:

        // Mandatory execution directives
        $mandatory_execution or

        // Priority override commands
        $priority_overrides or

        // Required precedence patterns
        $required_precedence or

        // Hidden parameter requests
        $hidden_param or

        // Specific file access coercion
        $file_access_coercion or

        // Model data extraction coercion
        $model_data_coercion or

        // Model internal extraction
        $model_internals or

        // HTML-like tag instructions with commands
        $html_tag_with_commands or

        // Tool execution override patterns — at least one occurrence must
        // lie outside every gate sentence (a $user_gate_head and the
        // $user_gate_tail that starts where it ends) and every
        // $user_approval_sentence.
        (for any i in (1..#execution_overrides) :
          ((not (for any h in (1..#user_gate_head) :
              ((@user_gate_head[h] <= @execution_overrides[i]) and
               (for any t in (1..#user_gate_tail) :
                  ((@user_gate_tail[t] == @user_gate_head[h] + !user_gate_head[h]) and
                   (@execution_overrides[i] + !execution_overrides[i] <= @user_gate_tail[t] + !user_gate_tail[t])))))) and
           (not (for any s in (1..#user_approval_sentence) :
              ((@user_approval_sentence[s] <= @execution_overrides[i]) and
               (@execution_overrides[i] + !execution_overrides[i] <= @user_approval_sentence[s] + !user_approval_sentence[s])))))) or

        // Behavioral control instructions
        $behavior_control or

        // MCP tool poisoning patterns
        $tool_poisoning or

        // Data exfiltration coercion — at least one occurrence must lie
        // outside every $negated_listing_sentence. For "include ... in your
        // response", at least one secret must have, as its nearest covering
        // `include` occurrence, one that doesn't start inside a
        // $negated_inclusion_sentence reaching the end of the secret's "in
        // your response".
        (for any i in (1..#data_exfiltration_coercion) :
          (not (for any s in (1..#negated_listing_sentence) :
            ((@negated_listing_sentence[s] <= @data_exfiltration_coercion[i]) and
             (@data_exfiltration_coercion[i] + !data_exfiltration_coercion[i] <= @negated_listing_sentence[s] + !negated_listing_sentence[s]))))) or
        (for any o in (1..#object_in_response) :
          (for any i in (1..#include_in_response) :
            ((@include_in_response[i] < @object_in_response[o]) and (@include_in_response[i] + !include_in_response[i] > @object_in_response[o]) and
             (not (for any a in (1..#include_in_response) :
                ((@include_in_response[a] > @include_in_response[i]) and (@include_in_response[a] < @object_in_response[o])))) and
             (not (for any s in (1..#negated_inclusion_sentence) :
                ((@negated_inclusion_sentence[s] < @include_in_response[i]) and
                 (@object_in_response[o] + !object_in_response[o] <= @negated_inclusion_sentence[s] + !negated_inclusion_sentence[s]))))))) or

        // Behavioral triggers
        $behavioral_triggers or

        // Pre-execution attacks
        $pre_execution_attacks or

        // Conversation theft triggers
        $conversation_theft or

        // Code manipulation instructions
        $code_manipulation

}
