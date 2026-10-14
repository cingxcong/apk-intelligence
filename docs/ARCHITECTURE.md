# Architecture and data flow

## Design goals

APK Intelligence is designed around five principles:

1. **Evidence before interpretation.** Preserve exact sample identity and source locations before producing conclusions.
2. **Static-only handling.** Treat the APK as an archive and byte sequence; never install or launch it.
3. **Bounded processing.** Limit downloads, archive expansion, string collection, external-tool time, and other potentially unbounded work.
4. **Visible coverage.** Record which parsers and tools ran, failed, timed out, or were skipped.
5. **Machine-readable outputs.** Use JSON for report metadata/findings and JSON Lines for potentially large evidence inventories.

## Pipeline

```text
Local APK / HTTPS URL
        |
        v
Input validation and bounded download
        |
        v
Sample identity (hashes) + ZIP/archive inventory
        |
        +----> Manifest / metadata extraction
        |
        +----> DEX fingerprints and bounded string scan
        |
        +----> Androguard class/method/instruction extraction (optional)
        |
        +----> JADX / Apktool / APKiD subprocesses (optional)
        |
        v
Evidence records + tool provenance + coverage/limitations
        |
        v
summary.md + manifest.json + findings.json + JSONL indexes
```

The diagram is conceptual: the exact stages available in a run depend on command options, installed dependencies, parser compatibility, and tool outcomes.

## Trust boundaries

- **Input boundary:** APK files and downloaded bytes are untrusted. Downloading is constrained to HTTPS and guarded against private/local destinations and oversized payloads.
- **Archive boundary:** ZIP members can be malformed or unusually large. Archive-entry and expanded-size limits constrain processing.
- **Subprocess boundary:** Optional tools are invoked with bounded timeouts and captured stdout/stderr. A non-zero exit or timeout is a coverage gap, not proof that the APK is malicious.
- **Interpretation boundary:** API names and printable strings are indicators only. They do not establish reachability, intent, or runtime behavior.
- **AI boundary:** AI-generated summaries must remain interpretations or hypotheses. They must not be silently promoted to observed facts.

## Evidence layers

| Layer | Examples | How to interpret |
|---|---|---|
| Sample identity | SHA-256, archive member hashes | Stable identifiers for the analyzed bytes |
| Direct observations | File names, DEX header fields, extracted metadata | Facts directly read from the input or a tool result |
| Parsed code evidence | Class/method descriptors, instructions, references | Parser-dependent; validate coverage and tool compatibility |
| Heuristic indicators | API/string pattern matches | Leads for investigation, not a malware verdict |
| Tool interpretations | Decompiled output, APKiD output | Preserve tool/version and raw logs; independently verify important claims |

## Output ownership

- `summary.md` is the entry point for humans and AI systems.
- `manifest.json` is the authority for sample identity, tool provenance, coverage, and limitations.
- `findings.json` contains structured indicators and evidence.
- `*.jsonl` files hold large inventories as one JSON object per line.
- `tool-logs/` preserves optional tool output for auditing.

See [REPORT_SCHEMA.md](REPORT_SCHEMA.md) for file-level details and [ANALYST_GUIDE.md](ANALYST_GUIDE.md) for an investigation workflow.
