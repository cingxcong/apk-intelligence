# APK Intelligence

Evidence-first Android APK reverse engineering and DEX fingerprinting.

## Status

Initial static-analysis workbench. It preserves the original sample hash and records tool provenance, limitations, and evidence references. APKs are inspected as data and are never installed or executed.

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -e '.[androguard]'
python -m apkintel analyze /path/to/app.apk --out analysis-output
```

Optional tools: `jadx`, `apktool`, and `apkid` are detected on `PATH` and used when available. The optional Androguard integration provides structured class/method metadata, instruction indexes, and cross-reference edges when supported by the installed version.

## Output

- `manifest.json` — sample identity, hashes, app metadata, tool versions, and coverage notes.
- `files.jsonl` — archive inventory and per-entry SHA-256 hashes.
- `dex.jsonl` — raw DEX fingerprints and header counts.
- `classes.jsonl`, `methods.jsonl` — structured code inventory.
- `instructions.jsonl` — instruction mnemonics/operands and method-local offsets when available.
- `references.jsonl` — parser-reported cross-reference edges.
- `strings.jsonl` — printable strings with source file and approximate character offsets.
- `findings.json` — evidence-backed indicators with explicit confidence/limitations.
- `summary.md` — compact analyst/AI overview.
- `tool-logs/` — stdout/stderr from optional tools.

## GitHub Actions

Open the **Actions** tab, select **APK Intelligence**, choose **Run workflow**, and provide an HTTPS APK URL. The workflow validates the destination, downloads with size limits, runs static analysis, and uploads a ZIP report as an artifact. Only analyze APKs you are authorized to inspect. Do not put secrets in the URL.

## Evidence model

Every finding should identify its source file and supporting value or tool output. Observed facts, heuristic indicators, and tool errors are kept separate. Instruction offsets are method-local unless explicitly labelled otherwise. String offsets are approximate positions in decoded text, not Dalvik instruction addresses. Reports disclose gaps due to obfuscation, unsupported bytecode, packing, dynamic loading, and parser/tool failures.

## Safety

- APKs are untrusted input and are never installed or executed.
- URL downloads require HTTPS, reject local/private destinations, validate redirects, and enforce a size cap.
- GitHub-hosted runners are ephemeral, but do not submit confidential APKs unless your repository and runner setup are appropriate.
- Treat decompiled output and strings as untrusted data.

## License

No license has been selected yet. Add a license before redistributing this project.
