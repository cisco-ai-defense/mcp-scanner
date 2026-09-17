; Java method/constructor declarations.
;
; Java MCP SDK detection (Spring AI, etc.) is annotation-driven —
; ``@Tool``, ``@McpTool`` attached to method declarations — so the
; primary value of this query is to feed both the function-name index
; and the annotation index pass with the canonical set of function-
; shaped nodes. The annotation collector
; (``_ts_collect_function_annotations``) walks the ``modifiers`` child
; from each match here, so we don't need a separate annotations.scm.
;
; ``modifiers`` carries marker_annotation / annotation children for
; Java's ``@Annotation(...)`` syntax; that's a tree-sitter-java
; convention shared by every recent grammar version.

(method_declaration
  name: (identifier) @func_name) @func_def

(constructor_declaration
  name: (identifier) @func_name) @func_def
