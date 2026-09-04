; C# method/constructor/local-function declarations.
;
; C# MCP SDK detection is attribute-driven — ``[McpServerTool]``,
; ``[McpServerToolType]`` — and attributes live in the
; ``attribute_list`` child of each declaration. The annotation
; collector reads them per-function, so we only need to enumerate
; the declaration shapes here.
;
; ``local_function_statement`` is included for parity with the
; ``FUNCTION_NODE_TYPES["c_sharp"]`` set the imperative walker uses;
; nested local functions don't typically carry MCP attributes but
; the cross-reference resolver needs to resolve them when MCP
; methods call out to local helpers.

(method_declaration
  name: (identifier) @func_name) @func_def

(constructor_declaration
  name: (identifier) @func_name) @func_def

(local_function_statement
  name: (identifier) @func_name) @func_def
