; Go MCP server instantiations.
;
; Go's SDK exposes a factory call (``mcp.NewServer(...)``) rather than
; a constructor — the receiver of the call is the imported SDK
; package alias. Two binding shapes:
;
;   server := mcp.NewServer(...)   ; short_var_declaration
;   var server = mcp.NewServer(...) ; var_declaration
;
; The Python side already collects the SDK aliases from the file's
; imports; we just identify the binding here. ``@class`` captures the
; field identifier (e.g. ``NewServer``) so the Python filter can
; verify it's a known factory before trusting the binding.

; Pattern 1: ``server := mcp.NewServer(...)``.
(short_var_declaration
  left: (expression_list (identifier) @target)
  right: (expression_list (call_expression
    function: (selector_expression
      operand: (_) @receiver
      field: (field_identifier) @class)))) @value

; Pattern 2: ``var server = mcp.NewServer(...)`` exposed via a
; ``var_spec`` in tree-sitter-go's ``var_declaration``.
(var_spec
  name: (identifier) @target
  value: (expression_list (call_expression
    function: (selector_expression
      operand: (_) @receiver
      field: (field_identifier) @class)))) @value
