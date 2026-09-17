; TypeScript MCP server instantiations.
;
; Captures local bindings whose right-hand side is a ``new`` of an MCP
; SDK class (``new McpServer(...)``, ``new Server(...)``, etc.) or a
; plain factory call to a known SDK class. The Python side filters the
; class identifier against ``_MCP_KNOWN_SERVER_CLASSES`` joined with
; the SDK classes pulled from the file's imports — the query just
; identifies *the binding*, the trust check stays in Python.
;
; Captures:
;   @target  — the local name receiving the binding.
;   @class   — the constructor / callee identifier (``McpServer``,
;              ``FastMCP``, etc.).
;   @value   — the instantiating expression (``new ...`` /
;              ``call_expression``) for downstream inspection.

; Pattern 1: ``const|let|var server = new McpServer(...)``.
;
; ``new_expression`` exposes the constructor under the ``constructor``
; field and the constructor itself can be either a plain identifier or
; a member expression like ``mcp.McpServer``. We capture the leaf
; identifier in both shapes.
(variable_declarator
  name: (identifier) @target
  value: (new_expression
    constructor: (identifier) @class)) @value

(variable_declarator
  name: (identifier) @target
  value: (new_expression
    constructor: (member_expression
      property: (property_identifier) @class))) @value

; Pattern 2: ``const server = McpServer(...)`` (factory call form).
;
; Matches both bare ``Class(...)`` and ``ns.Class(...)`` callees.
(variable_declarator
  name: (identifier) @target
  value: (call_expression
    function: (identifier) @class)) @value

(variable_declarator
  name: (identifier) @target
  value: (call_expression
    function: (member_expression
      property: (property_identifier) @class))) @value

; Pattern 3: ``server = new McpServer(...)`` (re-assignment).
(assignment_expression
  left: (identifier) @target
  right: (new_expression
    constructor: (identifier) @class)) @value

(assignment_expression
  left: (identifier) @target
  right: (new_expression
    constructor: (member_expression
      property: (property_identifier) @class))) @value
