; JavaScript low-level SDK registrations.
; Matches ``server.setRequestHandler(SchemaIdentifier, handler)`` —
; same shape as the TypeScript variant; see
; ``typescript/low_level.scm`` for the full rationale.
(call_expression
  function: (member_expression
    object: (_) @receiver
    property: (property_identifier) @method
    (#eq? @method "setRequestHandler"))
  arguments: (arguments) @args) @call
