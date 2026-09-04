; JavaScript capability registrations.
;
; tree-sitter-javascript uses the same node names as tree-sitter-
; typescript for the patterns we care about (``call_expression``,
; ``member_expression``, ``property_identifier``, ``arguments``), so
; the query body is identical to ``typescript/registrations.scm``. We
; keep a separate file per language because each query is compiled
; against a specific tree-sitter ``Language`` — the grammars are
; *shape-compatible* for us, but they're still distinct grammars.
(call_expression
  function: (member_expression
    object: (_) @receiver
    property: (property_identifier) @method
    (#match? @method "^(tool|registerTool|addTool|prompt|registerPrompt|addPrompt|promptTemplate|registerPromptTemplate|addPromptTemplate|resource|registerResource|addResource|resourceTemplate|registerResourceTemplate|addResourceTemplate)$"))
  arguments: (arguments) @args) @call
