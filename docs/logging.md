# Logging conventions

This document describes the operator-facing logging contract that the
MCP Scanner SDK targets going forward. New code should follow the
patterns described here; older modules will migrate opportunistically.

## TL;DR

* Use **lazy `%`-style** interpolation, never f-strings, for log calls.
* Encode payloads as **`key=value` fields** separated by spaces.
* **Sanitise** every value that may contain whitespace, `=`, or quotes.
* **Truncate** every value that comes from an external source (LLM
  responses, exception bodies from third-party libs).
* Get loggers through `mcpscanner.utils.logging_config.get_logger` so
  they share the SDK handler and respect `set_log_level`.
* Library logs go to **`stderr`**; result payloads go to **`stdout`**.

## Why a contract at all

The SDK is consumed by three audiences with different needs:

1. **Developers** running a one-shot CLI scan — they want readable
   English output and tolerate flexible formatting.
2. **CI pipelines** piping results into `jq`, dashboards, or artefact
   storage — they need stdout to stay clean and free of log noise.
3. **Operators** running the API server / a long-lived CLI in
   production — they ship logs to a log aggregator (CloudWatch
   Insights, Splunk KV_MODE, Datadog facets) and need each log line to
   parse mechanically.

A small contract keeps audience (3) viable without making (1) painful.

## Concretely

### Lazy `%`-style interpolation

```python
# Good — `%`-style: payload is only formatted when the level is enabled,
# and the format string remains a single recognisable identifier in
# log aggregators.
logger.info(
    "behavioral scan done mode=%s target=%s findings=%d non_safe=%d",
    scan_mode, scan_target, len(findings), non_safe,
)

# Avoid — f-strings: payload is always formatted (cost even when
# disabled), and the message text changes per call so the aggregator
# sees thousands of distinct "templates" instead of one.
logger.info(
    f"behavioral scan done mode={scan_mode} target={scan_target} "
    f"findings={len(findings)} non_safe={non_safe}"
)
```

### `key=value` field shape

Each log line consists of a stable **event prefix** (e.g.
`behavioral scan done`) followed by `key=value` fields. Values must
not contain whitespace, `=`, or quotes — sanitise them with
`sanitize_log_value` from `mcpscanner.utils.log_format`.

```python
from mcpscanner.utils.log_format import sanitize_log_value

logger.info(
    "behavioral file done path=%s findings=%d non_safe=%d duration_ms=%d",
    sanitize_log_value(accepted.path),
    len(findings), non_safe, ms,
)
```

When a single field can take multiple kinds (severities, languages),
**project each kind to its own field** rather than embedding a CSV:

```python
# Good — each severity is a first-class queryable field
sev_HIGH=2 sev_MEDIUM=1 sev_LOW=0 sev_SAFE=87

# Avoid — aggregators have to parse the value to chart per-severity
severities=H=2,M=1,L=0,S=87
```

### Truncation

Anything that came from outside the SDK process — LLM responses,
exception bodies thrown by third-party libraries, untrusted source
paths — must be truncated before it lands in a log line. Use
`truncate` from `mcpscanner.utils.log_format`:

```python
from mcpscanner.utils.log_format import truncate, ERROR_TRUNCATE

try:
    response = await client.call()
except Exception as e:
    logger.error(
        "external_call failed error_type=%s error=%s",
        type(e).__name__, truncate(e, ERROR_TRUNCATE),
        # exc_info=True still emits the full traceback if you need it;
        # truncate() only bounds the one-line summary.
        exc_info=True,
    )
```

Two reusable budgets are exported:

| Constant             | Default | Used for                                     |
|----------------------|--------:|----------------------------------------------|
| `ERROR_TRUNCATE`     |    400  | Exception messages, JSON decode errors, …    |
| `RESPONSE_DEBUG_MAX` |    500  | Raw LLM response dumps at DEBUG              |

### Getting a logger

```python
from mcpscanner.utils.logging_config import get_logger

logger = get_logger(__name__)
```

`get_logger` returns a configured logger with a `StreamHandler(stderr)`
attached and `propagate = False`, so it integrates cleanly with
`set_log_level`. Direct `logging.getLogger(__name__)` works too but
bypasses the SDK handler — fine for purely internal modules, but every
new module-level logger added to the SDK should prefer `get_logger`.

### Streams

`get_logger`, `setup_logger`, and the CLI / FastAPI entry points all
write log records to **`sys.stderr`**. Stdout is reserved for
machine-readable result payloads (`mcp-scanner ... > out.json`). If you
want logs in stdout, attach your own handler to the `mcpscanner` root
logger; do not change the SDK default.

### Correlation IDs

Where applicable (currently the alignment LLM client), each log site
emits a stable `request_id=<int>` that correlates initial requests,
retries, slow-response warnings, and completion lines for the same
logical call. Use these to slice traces in your aggregator instead of
relying on timestamps.

## Migration policy

* New modules: follow this contract.
* Touched modules: migrate the lines you edit in the same change.
* The behavioral pipeline + the static-analysis modules under
  `mcpscanner.core.static_analysis` were the first migration; see
  `mcpscanner/core/analyzers/behavioral/code_analyzer.py` and
  `mcpscanner/core/analyzers/behavioral/alignment/alignment_llm_client.py`
  for canonical examples.
