# MCP Tool Detection Troubleshooting

Use this guide when MCP Scanner reports fewer tools than you expect, or skips files you know register MCP capabilities. It describes how **behavioral** scanning decides what to analyze today, common false negatives, and workarounds.

For scan setup and output formats, see [Behavioral Scanning](behavioral-scanning.md). For npm package scans, see [npm Scanning](npm-scanning.md).

---

## Gate model overview

Behavioral capability extraction applies a series of gates per file. A registration must pass each gate (or fall into an documented exception) before it reaches LLM alignment analysis.

| Gate | What it checks | Primary code |
|------|----------------|--------------|
| **0 — Scan path** | Which command/analyzer runs on the file | `code_analyzer.py`, `js_code_analyzer.py` |
| **1 — MCP markers** | File contains SDK/MCP marker tokens | `_MCP_PREFILTER_RE` in `native_analyzer.py` |
| **2 — Registration form** | Decorator/call shape is recognized; handler/name resolved | `ContextExtractor`, `NativeAnalyzer._ts_parse_registration_args` |
| **3 — Trusted receiver** | Call is on a recognized server object (when provenance is known) | `NativeAnalyzer._ts_receiver_is_trusted` |
| **4 — File scanned** | Path is inside scan roots and not excluded | `JSBehavioralCodeAnalyzer`, directory walkers |

---

## Gate 0 — Scan path and command

**Most “missed tool” reports start here.** The command you run selects the analyzer pipeline.

| Command | JS/TS analyzer | Dynamic tool names |
|---------|----------------|--------------------|
| `mcp-scanner behavioral …` | `NativeAnalyzer` | Partial — some patterns emit **unresolved** stubs |
| `mcp-scanner npm-scan …` | `JSContextExtractor` | **Not supported** — non-literal names are dropped |

- **Behavioral** (`code_analyzer.py`): Python files use `ContextExtractor` first, then `NativeAnalyzer` fallback when zero tools are found. JS/TS always uses `NativeAnalyzer`.
- **npm-scan** (`js_code_analyzer.py` → `JSContextExtractor`): requires a **string-literal** tool name in the first argument; dynamic names bail out immediately.

```bash
# Prefer behavioral for local MCP server repos with dynamic registration
mcp-scanner behavioral /path/to/server/

# npm-scan is for published packages; it will miss dynamic tool tables
mcp-scanner npm-scan @scope/my-mcp-server
```

---

## Gate 1 — MCP markers (prefilter)

Before parsing, `NativeAnalyzer` checks `_has_mcp_markers()` against `_MCP_PREFILTER_RE`. Files with **no** matching tokens are skipped entirely.

### Markers the regex includes (not exhaustive)

Human greps often use `McpServer`, `fastmcp`, `@mcp.tool`. The prefilter also matches:

- **JS/TS:** `@modelcontextprotocol/sdk`, `McpServer`, `registerTool`, `registerPrompt`, `registerResource`, `registerResourceTemplate`, `registerPromptTemplate`, `setRequestHandler`
- **Kotlin / some SDKs:** `addTool`, `addPrompt`, `addResource`, `modelcontextprotocol.kotlin`
- **Go:** `modelcontextprotocol/go-sdk`
- **Java / Spring:** `io.modelcontextprotocol`, `org.springframework.ai`, `@McpTool`, `@Tool`
- **Rust:** `rmcp::`, `# [tool]`
- **PHP:** `# [Tool]`, `# [McpTool]`
- **Ruby:** `# @tool`
- **Python:** `fastmcp`, `mcp.server`, `FastMCP(`, `@mcp.tool`, `@server.call_tool`, …

### Nuance: `registerTool` vs bare `.tool(`

- A file that only calls `server.registerTool(...)` **can pass Gate 1** because `registerTool` is a marker — even without `new McpServer(...)` in the same file.
- A file that **only** uses `.tool(...)` with **no** SDK import, constructor, or other marker string anywhere in the file **fails Gate 1** and is never parsed.

**Symptom:** “Scanner ignored my server file entirely.”  
**Check:** Search the file for any prefilter token above; add an import or use a recognized registration API if the file is marker-free.

---

## Gate 2 — Registration form

### Python — primary vs broader detector

| Stage | Component | When it runs |
|-------|-----------|--------------|
| Primary | `ContextExtractor` | Always first for `.py` files |
| Broader | `NativeAnalyzer` Gap 8 (`_py_iter_programmatic_registrations`) | **Only when primary finds zero tools in that file** |

This shadowing matters: if the file has even one `@mcp.tool()` the broader pass **does not run**, so programmatic registrations in the same file are invisible.

#### Primary detector limitations

- **`@self.mcp.tool()`** — missed. `_get_decorator_name()` only handles `ast.Attribute` when the base is a simple `Name` (e.g. `@mcp.tool`), not `self.mcp`.
- **`@server.call_tool()`** in a file that also has `@mcp.tool()` — missed by broader detector due to shadowing.

#### Python workarounds

| Missed pattern | Quick fix |
|----------------|-----------|
| `@self.mcp.tool()` | Use `@mcp.tool()` on a module-level `mcp = FastMCP(...)` instance |
| `@server.call_tool()` alongside `@mcp.tool()` | Move low-level tools to a separate file |
| `mcp.add_tool(fn)` in same file as decorators | Separate file, or add a plain `@mcp.tool()` so primary finds something (not ideal — split files is better) |

### TypeScript / JavaScript — two sub-stages

Split Gate 2 into **method recognized** vs **handler/name resolved**. Many loop/table registrations fail at the second stage, not because `.tool()` is unknown.

#### Sub-stage A — method recognized

`NativeAnalyzer` walks call expressions for `.tool`, `.registerTool`, `.setRequestHandler`, Go `AddTool`, etc.

#### Sub-stage B — handler/name resolved

`_ts_parse_registration_args()` collects:

- First string literal → tool name
- Inline function/arrow → handler node
- Bare **identifier** → handler name (resolved later)

It does **not** treat member expressions like `obj.handler` or `t.fn` as handlers. A registration is kept only when:

```text
handler_node is not None  OR  handler_name is not None
```

(Gap 8 unresolved stubs additionally require `handler_name` or `name`.)

#### TypeScript examples

```typescript
// ✅ Name OK; handler = bare identifier → usually kept
server.tool("add", schema, handler);

// ❌ Often dropped — no literal name, handler not a bare id
server.tool(dynamicName, schema, fn);

// ⚠️ Call often seen; usually dropped at handler/name stage
tools.forEach(t => server.tool(t.name, schema, t.fn));
//   t.name → not a string literal
//   t.fn   → member expression, not bare identifier
```

#### npm-scan (Gate 0 reminder)

`JSContextExtractor._extract_tool_name()` returns `None` unless the first argument is a string literal — dynamic names never pass.

---

## Gate 3 — Trusted receiver

When `NativeAnalyzer` infers trusted server variable names from imports/constructors, registrations must call through those receivers (e.g. `server.tool`, not `other.tool`).

### Loose mode (factory / unconventional servers)

If **no** trusted receiver is inferred (`trusted_receivers` empty), `_ts_receiver_is_trusted()` returns **`True` for all registrations** — loose mode for backward compatibility.

- **Benefit:** Factory-built or oddly aliased servers may still be detected.
- **Cost:** More false positives from unrelated `.tool()` calls.

Strict filtering applies only when provenance detection succeeds.

---

## Gate 4 — File never scanned (optional)

Even when gates 1–3 would pass, the file may never be opened:

| Cause | Detail |
|-------|--------|
| Wrong extension | Behavioral JS/TS paths: `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts` |
| Outside scan roots | Path not under the directory/file you passed to the CLI |
| Build/vendor dirs | `node_modules`, `dist`, `build` skipped by behavioral walkers |
| Prefilter skip | Gate 1 failed — file read but dropped before parse |

---

## Symptom → gate quick reference

| Symptom | Likely gate |
|---------|-------------|
| Whole repo shows zero MCP tools | 0 (used `npm-scan`) or 1 (no markers) |
| Python file ignored except one decorator | 2 — broader detector shadowed |
| `@self.mcp.tool()` never found | 2 — Python primary |
| TS loop registers tools at runtime | 2B — handler/name not resolved |
| `server.tool("x", schema, obj.method)` missing | 2B — member handler |
| Only some SDK alias servers work | 3 — trusted receiver strict mode |
| Unusual server setup works but noisy | 3 — loose mode |
| File exists but never in logs | 4 — path/extension/exclusion |

---

## Known limitations → roadmap

These gaps are **by design today**. Planned engineering work targets the same symptoms:

| Troubleshooting symptom | Planned direction |
|-------------------------|-------------------|
| Loop / table registration | `_ts_iter_programmatic_registrations` + literal array name extraction |
| `server.tool(dynamicName, …)` silently dropped | Emit **unresolved** stub instead of drop (Gap 8 partial today) |
| `obj.handler` / bound methods | Member-expression and bound-method resolution |
| `npm-scan` vs behavioral split | Unify npm-scan on `NativeAnalyzer` |
| Python primary/broader shadowing | Run Gap 8 even when primary finds ≥1 tool in file |

When implementing fixes, add regression fixtures under `tests/static_analysis/` and extend this doc’s examples.

---

## Code references

| Topic | Location |
|-------|----------|
| MCP prefilter regex | `mcpscanner/core/static_analysis/native_analyzer.py` (~600–633) |
| Python primary extractor | `mcpscanner/core/static_analysis/context_extractor.py` |
| Behavioral file routing | `mcpscanner/core/analyzers/behavioral/code_analyzer.py` (~698–738) |
| npm-scan JS extractor | `mcpscanner/core/static_analysis/javascript/js_context_extractor.py` |
| TS registration args | `NativeAnalyzer._ts_parse_registration_args` |
| Trusted receiver / loose mode | `NativeAnalyzer._ts_receiver_is_trusted` (~2454–2487) |
| Unresolved stubs (Gap 8) | `NativeAnalyzer.extract_mcp_capability_contexts` (~1063–1091) |

---

## Related documentation

- [Behavioral Scanning](behavioral-scanning.md) — commands, LLM setup, output formats
- [npm Scanning](npm-scanning.md) — package scan mode and limitations
- [Static Scanning](static-scanning.md) — offline JSON / CI workflows
