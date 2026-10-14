# Security policy

## Scope

APK Intelligence processes Android APKs as untrusted data and is intended for authorized static analysis. It does not install or execute analyzed samples.

## Reporting a vulnerability

Please do not publish exploit details, credentials, private APK URLs, or sensitive sample data in a public issue. Use GitHub's private vulnerability reporting for this repository if it is enabled. Otherwise, contact the repository maintainer privately through a channel listed on their GitHub profile.

Include a concise description, affected commit/version, reproduction steps using a harmless test fixture where possible, and the potential impact. Avoid attaching confidential APKs unless the maintainer has agreed on a secure transfer method.

## Safe handling

- Analyze only APKs you are legally authorized to inspect.
- Treat APK files, manifests, strings, decompiled output, and tool logs as untrusted.
- Do not commit APK samples, private URLs, credentials, API keys, or generated decompilation output.
- Use private repositories and appropriate runner/data controls for confidential samples.
- Keep dependencies and optional analysis tools updated.

## Analysis limitations

Static indicators are not a verdict. Tool failures, parser gaps, packing, obfuscation, dynamic loading, and runtime-only behavior can affect coverage. See [the report schema](docs/REPORT_SCHEMA.md) for evidence conventions and limitations.
