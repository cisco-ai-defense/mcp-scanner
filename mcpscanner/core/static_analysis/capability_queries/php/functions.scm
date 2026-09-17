; PHP function definitions and class methods.
;
; PHP 8 ``#[Attribute(...)]`` syntax is parsed as ``attribute_list``
; child of the declaration (a sibling of ``visibility_modifier``,
; ``function`` keyword, ``name`` field, etc.). The annotation
; collector walks that subtree per-function, so this query only needs
; the canonical declaration shapes from
; ``FUNCTION_NODE_TYPES["php"]`` — ``function_definition`` for
; module-level functions and ``method_declaration`` for class
; methods. Both have a ``name`` field that exposes a ``name`` node
; (PHP's identifier-shaped node type).

(function_definition
  name: (name) @func_name) @func_def

(method_declaration
  name: (name) @func_name) @func_def
