# Finding evidence

Every active finding carries one evidence record. The record says what the scanner verified: a quote, a package identity, a probe result, or a completed negative check. It does not repeat severity, threat name, or analyzer name. Those stay on the finding.

CLI JSON, SDK JSON, and the HTTP API all emit this object. `raw_response` stays off the public finding payload.

## Record

```json
{
  "summary": "No instruction override defense found. Tool description lacks safeguards against users overriding system instructions.",
  "status": "observed",
  "sources": [
    {
      "location": {
        "type": "mcp_field",
        "locator": "/description",
        "line": null
      },
      "matched_text": null,
      "facts": [
        {"name": "check.patterns_checked", "value": 2},
        {"name": "check.patterns_matched", "value": 0},
        {"name": "check.minimum_matches", "value": 1}
      ]
    }
  ],
  "omitted_count": 0
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `summary` | string | One sentence, at most 500 characters. |
| `status` | string | `observed`, `scope_only`, or `unavailable`. |
| `sources` | array | Verified locations. At most 8. |
| `omitted_count` | integer | Sources dropped to stay within the cap. Negative checks (`value: false`) are kept first. |

`status` is `observed` when every published source has `matched_text` or at least one fact. It is `scope_only` when the location is known and nothing was verified there. It is `unavailable` when the producer attached no usable record. A false fact is an observed negative: the check ran and the thing was absent.

A source:

| Field | Type | Meaning |
| --- | --- | --- |
| `location.type` | string | `mcp_field`, `file`, `package`, or `probe`. |
| `location.locator` | string | JSON Pointer, relative file path, `pypi:name@version`, or a check id such as `MCPS-001`. An absolute path is published as the file name. |
| `location.line` | integer or null | 1-based line in the original text. Null for serialized parameters, packages, and probes. |
| `matched_text` | string or null | Exact substring, at most 240 characters. Null when the proof is a fact. |
| `facts` | array | Registered `{name, value}` pairs. At most 16. Unknown names are dropped. |

JSON Pointers escape `~` as `~0` and `/` as `~1`. The document root is `""`.

## Where it appears

On a tool, prompt, resource, or instructions result, `findings.<analyzer>_analyzer.evidence` is an array with one record per retained finding. `evidence.length` equals `total_findings`.

An analyzer that ran and found nothing has `total_findings: 0` and `evidence: []`. `is_safe` is `true` only for a completed scan with no active findings. Incomplete coverage is `is_safe: null`.

The HTTP API includes `evidence` and omits `threat_names` and `threat_summary`. CLI and SDK JSON keep those rollup fields and add `evidence`.

Package scans (`pypi-scan`, `npm-scan`) put the same record on each item in `findings[]`. A clean package has no finding rows. The CLI summary then shows one safe row with `evidence: []`.

## What each analyzer records

| Analyzer | Status | Location | What is verified |
| --- | --- | --- | --- |
| YARA | `observed` when a rule string is in the scanned text | `mcp_field`, such as `/description` | Exact matched text and line for description and instructions. Parameters stay at `/inputSchema` with `line: null`. |
| LLM | `observed` when the quote is in the submitted field; otherwise `scope_only` | `mcp_field` JSON Pointer from `field_hint` | Exact quote. A quote only inside a dumped schema blob is not published as `/inputSchema` text. |
| Behavioral, Python and JavaScript | `observed` when the quote is in the file; `scope_only` when alignment did not locate it | `file` | Exact quote and line. Python may add `code.role` (`input`, `operation`, `sink`) and `code.symbol`. JavaScript records `code.role: operation` only. |
| API | `scope_only` | `mcp_field` for the scanned field | The API returns a label, not a span. |
| VirusTotal | `observed` | `file` (basename) | `file.sha256`, malicious and suspicious counts, engine total, `virustotal.scanned_at`. No file bytes. |
| Vulnerable package | `observed` | `package`, `pypi:name@version` | `package.ecosystem`, `package.name`, `package.version`, `advisory.id`, `audit.source` (`pip-audit`). `matched_text` is null. |
| Prompt defense | `observed` | `mcp_field` `/description` or `/inputSchema` | `check.patterns_checked`, `check.patterns_matched`, `check.minimum_matches`. A missing defense has `matched_text: null`. A partial hit quotes the phrase that matched. All defenses present records `check.defenses_checked` and `check.defenses_present`. |
| Protocol | `observed` | `probe`, check id such as `MCPS-001` | `probe.completed: true`. `MCPS-003` also records `integrity.signature_header_present: false` and `integrity.signing_capability_present: false`. |
| Readiness heuristics and OPA | `observed` | `probe`, rule id such as `HEUR-001` | Missing timeout is `check.timeout_present: false`. A timeout that exists is `check.timeout_present: true`. A missing retry, schema, backoff, or auth field is `check.field_present: false`. Other rules record `probe.completed: true`. |
| Readiness LLM judge | `observed` | `probe`, the judge rule id | `probe.completed: true`. The judge's written reason stays in finding details and is not copied into `matched_text`. |
| Analyzer infrastructure failure | `observed` | `probe`, the analyzer name | `probe.completed: false`. Provider error text is not published. |

## Meta analyzer

Meta does not scan the tool and does not create a finding. It keeps or drops findings from the other analyzers.

A kept finding is unchanged, including its evidence. A dropped finding keeps that same evidence and adds `meta_false_positive`, `meta_reason`, and `meta_confidence` on the finding details. Those fields are the verdict. They are not a second evidence source.

## Custom analyzers

A custom analyzer sets `SecurityFinding.evidence` itself. If it does not, the serializer emits `unavailable` with no sources. Legacy `details.evidence` prose is not copied into `matched_text`.
