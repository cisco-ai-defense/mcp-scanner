; Kotlin function/method definitions for the per-file function index.
;
; The index ultimately holds ``name -> Node`` for every named callable so
; the cross-reference resolver can look up registered handlers by symbol
; (e.g. ``server.addTool(name = "add", handler = ::add)`` resolves
; ``::add`` to the ``function_declaration`` named ``add``). The
; consumer (``_ts_build_function_index_q``) only adds entries when
; ``@func_name`` is captured, so the unnamed-callable patterns below
; are deliberately captured for the *annotation* index pass — Kotlin
; can attach annotations to lambdas / anonymous functions / secondary
; constructors and we want the same nodes the imperative walker visits.
;
; Note: ``primary_constructor`` does not appear in the function-name
; index (no ``name`` field) but the imperative ``_ts_build_annotation_index``
; treats it as a function-shaped node, so we surface it here for parity.

(function_declaration
  name: (identifier) @func_name) @func_def

(secondary_constructor) @func_def

(primary_constructor) @func_def

(anonymous_function) @func_def

(lambda_literal) @func_def
