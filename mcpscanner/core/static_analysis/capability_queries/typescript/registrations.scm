; TypeScript capability registrations.
;
; Captures every call expression whose property matches an MCP SDK
; registration method name. Receiver-trust verification and argument
; parsing happen in Python — this query is intentionally permissive so
; the existing receiver allow-list (``_ts_receiver_is_trusted``) stays
; the single source of truth.
;
; Capability methods covered:
;   tool / registerTool / addTool
;   prompt / registerPrompt / addPrompt
;     prompttemplate / registerPromptTemplate / addPromptTemplate
;   resource / registerResource / addResource
;     resourcetemplate / registerResourceTemplate / addResourceTemplate
;
; Captures:
;   @receiver  — the object the method is called on (typically the MCP
;                server instance, e.g. ``server`` in
;                ``server.tool(...)``).
;   @method    — the property identifier (``tool``, ``registerTool``...).
;   @args      — the arguments node, passed verbatim to
;                ``_ts_parse_registration_args`` for handler / name
;                extraction. Optional in the grammar's strict shape; we
;                capture it when present and the Python side tolerates
;                a missing arguments node.
;   @call      — the surrounding ``call_expression`` (so the Python
;                walker can pass it to receiver-verification helpers
;                without re-finding it).
(call_expression
  function: (member_expression
    object: (_) @receiver
    property: (property_identifier) @method
    (#match? @method "^(tool|registerTool|addTool|prompt|registerPrompt|addPrompt|promptTemplate|registerPromptTemplate|addPromptTemplate|resource|registerResource|addResource|resourceTemplate|registerResourceTemplate|addResourceTemplate)$"))
  arguments: (arguments) @args) @call
