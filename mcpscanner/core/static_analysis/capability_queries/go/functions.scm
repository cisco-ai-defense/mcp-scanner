; Go function definitions used to resolve handler-by-name references.
;
; Both ``function_declaration`` and ``method_declaration`` expose the
; symbol name via the ``name`` field. We don't need to track method
; receivers here — handler names referenced inside an MCP registration
; are resolved against the file-scope index, which folds methods and
; functions into the same lookup table.

(function_declaration
  name: (identifier) @func_name) @func_def

(method_declaration
  name: (field_identifier) @func_name) @func_def
