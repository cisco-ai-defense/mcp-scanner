; Go capability registrations.
;
; Two registration shapes appear in the Go SDK:
;
;   1. Package-level call:  ``mcp.AddTool(server, &mcp.Tool{...}, fn)``
;      Receiver is the imported package alias (typically ``mcp``).
;      The first positional argument is the server, the rest are the
;      tool definition + handler — consumed by Python in
;      ``_ts_parse_registration_args``.
;
;   2. Method on a server value: ``server.AddTool(...)`` (some Go SDK
;      revisions expose a method form). Same shape as the JS-style
;      ``selector_expression`` lookup.
;
; Both shapes are ``call_expression`` with a ``selector_expression``
; callee in tree-sitter-go.
;
; Captures:
;   @receiver — the package alias / receiver value.
;   @method   — the field identifier (``AddTool``, ``AddPrompt``...).
;   @args     — the argument_list node.
;   @call     — the surrounding call_expression.
(call_expression
  function: (selector_expression
    operand: (_) @receiver
    field: (field_identifier) @method
    (#match? @method "^(AddTool|RegisterTool|Tool|AddPrompt|RegisterPrompt|Prompt|AddResource|RegisterResource|Resource|AddResourceTemplate|RegisterResourceTemplate|AddPromptTemplate|RegisterPromptTemplate)$"))
  arguments: (argument_list) @args) @call
