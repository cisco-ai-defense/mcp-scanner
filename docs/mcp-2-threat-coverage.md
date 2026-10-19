# MCP 2.0 threat coverage

This maps the July 28, 2026 MCP protocol PRD to scanner behavior. A finding
about an advertised risk does not prove exploitation. The scanner never
dereferences schema URLs or invokes tools during these checks.

| Threat area | Scan-time coverage | What requires an observed client/server exchange |
| --- | --- | --- |
| External, relative, and private `$ref` in tool input/output schemas | `schema` analyzer flags external and private references (`MCPS-011`) in live and static tool scans. Relative references and local fragments do not make a tool unsafe. No referenced content is fetched. | Whether a client resolves a reference, whether its contents change, and whether it reaches a private service. |
| Protocol headers | `protocol` command negotiates 2026-07-28 and probes missing/mismatched `Mcp-Method` on read-only `tools/list` (`MCPS-010`). It reports an incomplete probe (`MCPS-012`) if tool listing cannot be assessed. | Header consistency on methods that cannot be safely probed without an authenticated workflow, including `Mcp-Name` on calls. |
| Extensions and Tasks | Discovery and tools work with MCP 2.0; no extension allowlist or Tasks verdict is emitted. | Whether task results are scoped, expire, time out, and resist replay across clients. |
| Elicitation | Existing static source and text analyzers may identify suspicious wording; the scanner does not initiate elicitation. | Whether `InputRequiredResult` asks for credentials or uses urgency during an actual tool workflow. |
| MCP Apps | Resource scans can inspect declared resources as text. There is no app-rendering or browser sandbox verdict. | Script execution, cross-origin access, postMessage handling, and exfiltration from an embedded app. |
| Sampling injection | Tool descriptions, instructions, prompts, and resource text can be scanned for injection patterns. | Whether server-driven sampling requests alter a model's behavior or leak data. |
| MRTR replay and state hijack | No passive verdict. The `protocol` command avoids treating repeated `tools/list` as a replay attack on MCP 2.0. | Correlation of request IDs, auth context, state, and results across an instrumented client/server session. |
| Shared-cache poisoning and server shadowing | No single-server verdict. Cache hints (`ttlMs`, `cacheScope`) describe freshness and caller sharing; they do not authenticate the server that produced a response. | A host or gateway using a shared cache must key entries by verified server origin (and private entries by authorization context). Detecting a name/version collision requires two controlled origins and observation of the client's cache behavior. |
| Split payloads and exfiltration | Existing text/YARA/LLM analyzers inspect material present at scan time; schema reference locations are reported. | Payload reassembly across tool calls, actual outbound transfers, and client behavior after rendering or dereferencing. |

For `resources/read`, the request `uri` is a resource identifier, not the MCP
server origin. `tools/list` has no resource URI parameter. Matching method and
parameters alone therefore cannot prove that a shared cache entry came from
the intended server. See the [MCP caching draft](https://modelcontextprotocol.io/specification/draft/server/utilities/caching)
and the [TypeScript SDK cache-store guidance](https://ts.sdk.modelcontextprotocol.io/v2/api/@modelcontextprotocol/client/client/client.html#responsecachestore).

Use `mcp-scanner --analyzers schema remote --server-url URL` for advertised tool
references, `mcp-scanner --analyzers schema --raw static --tools tools.json` for
offline fixtures, and `mcp-scanner protocol --server-url URL` for unauthenticated
HTTP protocol probes. The `schema` analyzer is opt-in for live and offline scans.
