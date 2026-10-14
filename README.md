# APK Intelligence

Evidence-first Android APK reverse engineering and DEX fingerprinting.

## Status

Initial scaffold in progress. This project performs static analysis only; it never executes the target APK. It preserves the original sample hash and records tool provenance, limitations, and evidence references.

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
python -m apkintel analyze /path/to/app.apk --out analysis-output
```

Optional tools: `jadx`, `apktool`, and `apkid` are detected on `PATH` and used when available. Androguard extraction is optional and may require a compatible version of its API.

## Output

- `manifest.json` — sample identity, hashes, tool versions, and run metadata.
- `files.jsonl` — archive inventory and hashes.
- `strings.jsonl` — printable strings found in APK/DEX/native files.
- `dex.jsonl` — DEX header fingerprints and optional parsed class/method metadata.
- `findings.json` — evidence-backed static indicators and explicit coverage notes.
- `summary.md` — compact human/AI-oriented overview.
- `tool-logs/` — stdout/stderr from optional tools.

## GitHub Actions

Run **APK Intelligence** from the Actions tab and provide an HTTPS APK URL. The workflow validates the destination, downloads with size limits, runs static analysis, and uploads a ZIP report as an artifact. Only analyze APKs you are authorized to inspect. Never put secrets in the URL.

## Evidence model

Every finding should identify its source file and supporting value or tool output. Observed facts, heuristic indicators, and tool errors are kept separate. Static analysis cannot prove intent and cannot fully recover packed, obfuscated, encrypted, or dynamically loaded code.

## Safety

- APKs are untrusted input and are never installed or executed.
- URL downloads require HTTPS, reject local/private destinations, validate redirects, and enforce a size cap.
- GitHub-hosted runners are ephemeral, but do not submit confidential APKs unless your repository and runner setup are appropriate.
- Treat decompiled output and strings as untrusted data.

## License

No license has been selected yet. Add a license before redistributing this project.
