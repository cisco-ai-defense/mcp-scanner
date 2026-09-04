; Kotlin MCP registrations: ``server.addTool(...) { ... }`` and friends.
;
; Two patterns capture the two shapes tree-sitter-kotlin produces:
;
;   1. Plain registration (no trailing lambda):
;        server.addTool(name = "add", handler = ::add)
;
;      tree:
;        call_expression
;          navigation_expression { server, addTool }
;          value_arguments
;
;   2. Registration with a trailing lambda (the canonical SDK form):
;        server.addTool(name = "add") { request -> ... }
;
;      tree:
;        call_expression                    -- outer wrapping
;          call_expression                  -- inner = the registration
;            navigation_expression { server, addTool }
;            value_arguments
;          annotated_lambda                 -- carries the body
;
; Both patterns expose the same captures so the consumer
; (``_collect_q_registrations``) doesn't need a Kotlin special-case:
;
;   @receiver  -- the object on the LHS of the dot ("server")
;   @method    -- the method identifier ("addTool")
;   @args      -- the value_arguments node
;   @call      -- the inner registration call (semantic anchor —
;                 used for trust check, arg parsing, and as the
;                 "registration node" stored in capability contexts)
;   @lambda    -- (pattern 2 only) the trailing lambda; used to
;                 populate ``handler_node`` when no inline handler
;                 sits inside the value_arguments

(call_expression
  (navigation_expression
    (_) @receiver
    (identifier) @method)
  (value_arguments) @args) @call

(call_expression
  (call_expression
    (navigation_expression
      (_) @receiver
      (identifier) @method)
    (value_arguments) @args) @call
  (annotated_lambda) @lambda)
