<div align="center">

# APK Intelligence

**Evidence-first Android APK triage, DEX inventory, and static-analysis reporting.**

A reproducible workflow for analysts, developers, and AI-assisted review—with traceable evidence, explicit coverage, and honest limitations.

[![CI](https://github.com/cingxcong/apk-intelligence/actions/workflows/ci.yml/badge.svg)](https://github.com/cingxcong/apk-intelligence/actions/workflows/ci.yml)
[![Tests](https://github.com/cingxcong/apk-intelligence/actions/workflows/tests.yml/badge.svg)](https://github.com/cingxcong/apk-intelligence/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Analysis](https://img.shields.io/badge/Analysis-static%20only-0A7B83)](#security-model)

</div>

---

## At a glance

APK Intelligence inspects Android APK files **as data**. It does not install, launch, or execute the sample. It records cryptographic hashes, archive inventory, manifest metadata, printable strings, DEX fingerprints, structured code evidence when available, and heuristic indicators.

| Goal | What you get |
|---|---|
| Identify the exact sample | SHA-256 and supporting file hashes, archive inventory, package metadata when available |
| Understand code coverage | DEX/class/method counts, tool availability, parser status, and explicit limitations |
| Investigate indicators | Findings linked to source files, matched values, and method-level evidence when available |
| Reproduce and automate | CLI workflow, JSON/JSONL outputs, captured tool logs, and GitHub Actions artifacts |
| Support human and AI review | A concise `summary.md`, documented report fields, stable evidence files, and claim-type guidance |

> **Important:** A detected API, string, or heuristic pattern is not proof of malicious behavior. Interpret every finding alongside its evidence and coverage status.

## Quick start

### 1. Install

Python 3.10 or newer is required.

```bash
python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -e '.[androguard]'
```

### 2. Analyze a local APK

```bash
python -m apkintel analyze /path/to/app.apk --out analysis-output
```

### 3. Review the report

Start with these files, in this order:

1. `summary.md` — quick orientation for an analyst or AI assistant.
2. `manifest.json` — sample identity, tool versions, coverage, and limitations.
3. `findings.json` — structured indicators and evidence objects.
4. `classes.jsonl`, `methods.jsonl`, and `instructions.jsonl` — code-level detail when extraction is available.
5. `tool-logs/` — raw output and errors from optional tools.

See the [report schema](docs/REPORT_SCHEMA.md) and [analyst guide](docs/ANALYST_GUIDE.md) for interpretation and examples.

## Run an analysis with GitHub Actions

1. Open the repository's **Actions** tab.
2. Select **APK Intelligence** and choose **Run workflow**.
3. Enter an HTTPS URL for an APK you are authorized to inspect.
4. Keep the optional-tool and Androguard skip switches **unchecked** for the fullest supported analysis.
5. When the run finishes, download the `apk-intelligence-report-<run-id>` artifact and inspect its files directly.

The workflow enforces a configurable download-size limit, runs tests, performs static analysis, and uploads the generated report without including the downloaded sample APK. Artifacts are retained for seven days by default. External tools may be unavailable, time out, or partially fail; review the manifest and tool logs rather than assuming every stage succeeded.

## Report layout

```text
analysis-output/
├── summary.md                 # Human/AI entry point
├── manifest.json              # Identity, provenance, coverage, limitations
├── findings.json              # Structured findings + evidence
├── files.jsonl                # Archive inventory + per-entry hashes
├── dex.jsonl                  # DEX fingerprints and header data
├── classes.jsonl              # Class inventory (when supported)
├── methods.jsonl              # Method inventory (when supported)
├── instructions.jsonl          # Method-local instruction evidence
├── references.jsonl            # Parser-reported reference edges
├── strings.jsonl               # Printable string candidates
├── tool-logs/                  # Captured tool stdout/stderr
└── jadx/ and apktool/          # Optional tool outputs, when produced
```

Files that depend on a parser or optional tool may be empty, omitted, or incomplete when that capability is unavailable. Always use `manifest.json` to understand actual coverage. JSONL files contain one JSON object per line and are designed for streaming and automated processing.

## Capabilities

- **Sample identity:** cryptographic hashes and archive-member inventory.
- **APK metadata:** package/version/permissions when exposed by the parser.
- **DEX inspection:** raw fingerprints and header counts.
- **Code inventory:** class and method descriptors, access flags, code metadata, instruction mnemonics/operands, and method-local offsets when supported.
- **String and indicator triage:** printable string candidates and bounded heuristic matches with source locations.
- **Optional tooling:** JADX, Apktool, and APKiD when installed and enabled.
- **Operational transparency:** tool versions, exit statuses, captured logs, coverage notes, and explicit limitations.

This is a static-analysis workbench, not a full Android emulator, dynamic instrumentation platform, or verdict engine.

## Repository map

```text
apk-intelligence/
├── .github/
│   └── workflows/             # CI, tests, and on-demand APK analysis
├── apkintel/
│   ├── cli.py                 # Analysis pipeline and report generation
│   └── downloader.py          # Guarded HTTPS APK download
├── docs/
│   ├── ANALYST_GUIDE.md       # How to read and correlate evidence
│   ├── ARCHITECTURE.md        # Pipeline and trust boundaries
│   └── REPORT_SCHEMA.md       # Output files and evidence conventions
├── tests/                     # Regression and safety tests
├── CONTRIBUTING.md
├── SECURITY.md
├── pyproject.toml
└── README.md
```

## Security model

- APKs are untrusted input and are never installed or executed by this project.
- URL downloads require HTTPS, validate destinations and redirects, and enforce a size cap.
- Static analysis cannot reliably reveal behavior hidden by packing, obfuscation, dynamic loading, encryption, or runtime-only execution.
- Treat strings, decompiled source, manifests, and tool output as untrusted content.
- Do not upload confidential samples to public repositories or workflows without authorization and an appropriate data-handling setup.

Read [SECURITY.md](SECURITY.md) before submitting samples or reporting a vulnerability.

## Development

```bash
python -m pip install -e '.[androguard]'
python -m pytest -q
```

Contributions should preserve the evidence-first model: separate observed facts from heuristic indicators, attach source locations, keep parser/tool failures visible, and avoid overstating conclusions. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Project status

APK Intelligence is an evolving static-analysis workbench. Output fields and tool coverage may change as parser compatibility and evidence extraction improve. Check the report's own schema, tool versions, and coverage fields before comparing results across versions.

---

<div align="center">

**Traceable evidence. Reproducible analysis. Explicit uncertainty.**

</div>
