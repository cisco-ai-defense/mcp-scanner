; TypeScript low-level SDK registrations.
;
; The TypeScript low-level Server uses ``setRequestHandler`` with a
; schema identifier as the first argument, not a method-name suffix:
;
;   server.setRequestHandler(CallToolRequestSchema, async (req) => {})
;
; We only match the call shape; the schema identifier is mapped to a
; capability kind in Python (``_LOW_LEVEL_SCHEMA_TO_CAPABILITY``) so
; the mapping stays in one place and supports
; ``Schemas.CallToolRequestSchema`` style references too.
;
; Captures:
;   @receiver  — the object the method is called on.
;   @method    — must be ``setRequestHandler``.
;   @args      — the arguments node containing the schema identifier
;                + handler.
;   @call      — the surrounding call_expression.
(call_expression
  function: (member_expression
    object: (_) @receiver
    property: (property_identifier) @method
    (#eq? @method "setRequestHandler"))
  arguments: (arguments) @args) @call
