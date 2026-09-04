; JavaScript MCP server instantiations.
; tree-sitter-javascript shape matches tree-sitter-typescript for the
; binding patterns we care about; see
; ``typescript/instantiations.scm`` for per-pattern rationale.

(variable_declarator
  name: (identifier) @target
  value: (new_expression
    constructor: (identifier) @class)) @value

(variable_declarator
  name: (identifier) @target
  value: (new_expression
    constructor: (member_expression
      property: (property_identifier) @class))) @value

(variable_declarator
  name: (identifier) @target
  value: (call_expression
    function: (identifier) @class)) @value

(variable_declarator
  name: (identifier) @target
  value: (call_expression
    function: (member_expression
      property: (property_identifier) @class))) @value

(assignment_expression
  left: (identifier) @target
  right: (new_expression
    constructor: (identifier) @class)) @value

(assignment_expression
  left: (identifier) @target
  right: (new_expression
    constructor: (member_expression
      property: (property_identifier) @class))) @value
