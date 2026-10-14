# Report schema and evidence rules

## Files

| File | Purpose |
|---|---|
| `manifest.json` | Sample identity, hashes, timestamps, tool inventory, coverage and limitations |
| `files.jsonl` | APK archive entries, CRC, sizes and SHA-256 |
| `dex.jsonl` | DEX raw-byte hashes and selected header fields with byte-range references |
| `classes.jsonl` | Parsed class descriptors when Androguard support is available |
| `methods.jsonl` | Parsed method names, descriptors and access flags when available |
| `strings.jsonl` | Printable string candidates with source archive path and approximate byte offset |
| `findings.json` | Structured findings and evidence objects |
| `summary.md` | Compact analyst and AI orientation |
| `tool-logs/` | Captured output from optional tools |

## Claim types

- `observed_fact`: directly read from the archive or an exact tool result.
- `heuristic_indicator`: a pattern or API-name match that may indicate a behavior but does not prove it.
- Future semantic analysis should use a separate `tool_interpretation` claim type and include the tool/version and its raw evidence.
- AI-generated explanations should be labelled as hypotheses, never promoted to facts without corroborating evidence.

## Evidence quality

Hashes identify exact byte sequences. Archive paths identify the evidence container. DEX header offsets are exact. Printable string offsets are explicitly approximate because the current pass uses a decoded text view; they are not Dalvik instruction offsets. Class/method rows depend on parser compatibility and must be read alongside `manifest.json` coverage status.

## Security limits

This project does not execute the APK, emulate the Android runtime, bypass application protections, or claim that static analysis sees dynamically downloaded/decrypted code. A matching API string is not proof of reachable behavior or malicious intent. Preserve the original APK separately and record its SHA-256 when sharing findings.
