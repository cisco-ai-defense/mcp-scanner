; JavaScript function definitions.
; tree-sitter-javascript node names match tree-sitter-typescript for
; these shapes; see ``typescript/functions.scm`` for the rationale on
; each pattern.

(function_declaration
  name: (identifier) @func_name) @func_def

(function_expression
  name: (identifier) @func_name) @func_def

(method_definition
  name: (property_identifier) @func_name) @func_def

(variable_declarator
  name: (identifier) @func_name
  value: (arrow_function) @func_def)

(variable_declarator
  name: (identifier) @func_name
  value: (function_expression) @func_def)

(assignment_expression
  left: (identifier) @func_name
  right: (arrow_function) @func_def)

(assignment_expression
  left: (identifier) @func_name
  right: (function_expression) @func_def)
