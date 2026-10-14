# Analyst guide

This guide provides a repeatable way to read an APK Intelligence report without overstating what static analysis can prove.

## Recommended review order

### 1. Confirm sample identity

Open `manifest.json` and record the SHA-256, package name/version if available, file size, analysis timestamp, and tool versions. Compare the SHA-256 with the sample you intended to analyze. A package name alone is not a unique sample identity.

### 2. Check coverage before conclusions

Review parser status, DEX count, class/method extraction status, optional-tool status, truncation flags, and warnings in the manifest. Read the corresponding files in `tool-logs/` for non-zero exits, timeouts, or partial decompilation. Empty evidence files do not necessarily mean the app contains no code; a capability may have been skipped or unavailable.

### 3. Read the findings as leads

For each finding, ask:

- What exactly matched?
- Which archive member or code location supports it?
- Is the claim a direct observation or a heuristic indicator?
- Is the evidence linked to a specific class/method/instruction?
- Could the API be used for a benign purpose?
- What additional evidence would confirm or disprove the hypothesis?

Do not label an APK malicious based only on a suspicious API name, string, permission, or library.

### 4. Correlate code evidence

When available, search `classes.jsonl`, `methods.jsonl`, and `instructions.jsonl` for the class or method referenced by a finding. Instruction offsets are method-local code offsets, not absolute APK/DEX file offsets. String offsets are approximate positions in decoded text and must not be treated as instruction addresses.

### 5. Review tool output

JADX, Apktool, and APKiD are supporting tools, not ground truth. Preserve tool names, versions, statuses, and raw logs. Decompiled output can be incomplete because of obfuscation, unsupported bytecode, malformed inputs, or tool errors.

### 6. Write a defensible conclusion

A good conclusion separates:

- **Observed:** directly supported by the archive or a tool result.
- **Indicated:** a pattern that merits further review.
- **Unknown:** behavior that this static pass cannot establish.
- **Next steps:** the exact evidence needed for validation.

## AI-assisted review prompt

When giving a report to an AI assistant, use a constrained prompt such as:

> Analyze this APK Intelligence report using only evidence present in the supplied files. Start with manifest coverage and limitations. Separate observed facts from heuristic indicators and hypotheses. For each conclusion, cite the exact report file and relevant field/value. Do not call the APK malicious solely because an API, string, permission, or library is present. Explicitly list what cannot be determined from static analysis.

## Comparison checklist

Before comparing two reports, verify that the sample hashes differ or match as expected, the analyzer versions are comparable, the same optional tools were enabled, the parser versions and coverage are similar, and neither report is truncated. Differences in tool versions or coverage can explain differences in output.

## Limits

Static analysis does not execute the application or establish what happens on a live device. Runtime behavior, remote configuration, decrypted payloads, server-side decisions, and environment-dependent code may not be visible in a static report.
