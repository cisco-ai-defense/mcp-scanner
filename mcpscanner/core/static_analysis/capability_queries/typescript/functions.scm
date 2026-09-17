; TypeScript function definitions used to build the per-file
; ``name -> definition_node`` index consumed by registrations whose
; handler is a bare identifier reference (e.g.,
; ``server.tool("add", schema, addImpl)``).
;
; The imperative walker recorded:
;   1. Named function/method declarations whose ``name`` field exists.
;   2. Arrow / function expressions assigned to a local via
;      ``const fn = ...`` or ``fn = ...``.
;
; Each pattern emits a uniform ``@func_name`` + ``@func_def`` capture
; pair so the Python loader can build the index without distinguishing
; pattern indices.

; Pattern 1: named function declaration.
(function_declaration
  name: (identifier) @func_name) @func_def

; Pattern 2: named function expression (rare in modern TS but supported).
(function_expression
  name: (identifier) @func_name) @func_def

; Pattern 3: methods inside class bodies.
(method_definition
  name: (property_identifier) @func_name) @func_def

; Pattern 4: ``const handler = (args) => { ... }``.
;
; ``lexical_declaration`` wraps a ``variable_declarator`` whose value
; is the arrow function. We capture the declarator name as @func_name
; and the arrow function itself as @func_def.
(variable_declarator
  name: (identifier) @func_name
  value: (arrow_function) @func_def)

; Pattern 5: ``const handler = function namedOrAnon() { ... }``.
(variable_declarator
  name: (identifier) @func_name
  value: (function_expression) @func_def)

; Pattern 6: ``handler = (args) => { ... }`` (re-assignment).
(assignment_expression
  left: (identifier) @func_name
  right: (arrow_function) @func_def)

; Pattern 7: ``handler = function() { ... }`` (re-assignment).
(assignment_expression
  left: (identifier) @func_name
  right: (function_expression) @func_def)
