; Rust function items.
;
; The rmcp SDK uses attribute macros (``#[tool]``, ``#[mcp::tool]``,
; ``#[tool_router]``) for MCP capability annotation. Attribute items
; precede the function as siblings under the same parent
; (``source_file`` for free functions, ``declaration_list`` for
; ``impl`` blocks); the annotation collector handles the sibling
; navigation imperatively, so we only need the function declaration
; shape here.
;
; ``impl_item`` is intentionally omitted — the imperative walker
; explicitly excludes it via ``_TS_NON_FUNCTION_NODE_TYPES`` because
; ``impl`` blocks aren't function bodies; they contain function items
; that we already match individually.

(function_item
  name: (identifier) @func_name) @func_def
