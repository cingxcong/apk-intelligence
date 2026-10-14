# Report schema and evidence rules

## Files

| File | Purpose |
|---|---|
| `manifest.json` | Sample identity, hashes, timestamps, tool inventory, app metadata, coverage and limitations |
| `files.jsonl` | APK archive entries, CRC, sizes and SHA-256 |
| `dex.jsonl` | DEX raw-byte hashes, header fingerprints and header byte-range references |
| `classes.jsonl` | Parsed class descriptors and inheritance metadata when Androguard support is available |
| `methods.jsonl` | Parsed method descriptors, access flags, code hashes/sizes, and instruction counts when available |
| `instructions.jsonl` | Decoded instruction mnemonic/operands and byte offsets within each method's code stream when exposed by Androguard |
| `references.jsonl` | Method cross-reference edges returned by the parser |
| `strings.jsonl` | Printable string candidates with source archive path and approximate character offset |
| `findings.json` | Structured findings and evidence objects |
| `summary.md` | Compact analyst and AI orientation |
| `tool-logs/` | Captured output from optional tools |

## Claim types

- `observed_fact`: directly read from the archive or an exact tool result.
- `heuristic_indicator`: a pattern or API-name match that may indicate a behavior but does not prove it.
- Future semantic analysis should use a separate `tool_interpretation` claim type and include the tool/version and its raw evidence.
- AI-generated explanations should be labelled as hypotheses, never promoted to facts without corroborating evidence.

## Evidence quality

Hashes identify exact byte sequences. Archive paths identify the evidence container. DEX header offsets are exact. Instruction offsets, when available, are offsets within the method's code stream, not absolute offsets in the APK or DEX file. Printable string offsets are explicitly approximate character positions in decoded text; they are not byte or instruction offsets. Class/method/reference rows depend on parser compatibility and must be read alongside `manifest.json` coverage status.

## Security limits

This project does not execute the APK, emulate the Android runtime, bypass application protections, or claim that static analysis sees dynamically downloaded/decrypted code. A matching API string is not proof of reachable behavior or malicious intent. Preserve the original APK separately and record its SHA-256 when sharing findings.
