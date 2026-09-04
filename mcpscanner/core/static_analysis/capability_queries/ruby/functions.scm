; Ruby method definitions.
;
; Ruby MCP SDKs use comment-style annotations (``# @tool name: "..."``)
; that precede a method definition as a SIBLING ``comment`` node at
; the same nesting level. The annotation collector walks
; ``prev_sibling`` chains per-function, so this query just enumerates
; the declaration shapes from ``FUNCTION_NODE_TYPES["ruby"]``.
;
; ``method`` covers ``def name(args); end``; ``singleton_method``
; covers ``def self.name(args); end`` (class methods). Both have a
; ``name`` field with an ``identifier`` child.

(method
  name: (identifier) @func_name) @func_def

(singleton_method
  name: (identifier) @func_name) @func_def
