; Kotlin MCP server instantiations: ``val server = Server(...)``.
;
; tree-sitter-kotlin parses this as:
;
;   property_declaration
;     variable_declaration
;       identifier              -- the local name ("server")
;     call_expression
;       identifier              -- the constructor / factory ("Server")
;       value_arguments
;
; ``var`` declarations parse with the same shape; ``val`` and ``var``
; differ only by the leading keyword token, which is unnamed and
; therefore not part of the AST shape we match on.
;
; The receiver-trust pipeline (``_collect_mcp_instances_q``) admits
; the binding when ``@class`` is a known MCP server class derived
; from ``import io.modelcontextprotocol.kotlin.sdk.server.Server``.
;
; Captures:
;   @target  -- the local name being bound
;   @class   -- the constructor identifier
;   @value   -- the call expression (kept for symmetry with TS/JS/Go)

(property_declaration
  (variable_declaration
    (identifier) @target)
  (call_expression
    (identifier) @class
    (value_arguments)) @value)
