# Contributing

Thank you for helping improve APK Intelligence. Contributions should make analysis more reproducible, explainable, safe, and easier for both human analysts and automated tooling to consume.

## Before opening a change

1. Create a focused branch and describe the problem or intended improvement.
2. Add or update tests for changed behavior, report fields, and detection rules.
3. Run `python -m pytest -q`.
4. Update the relevant documentation when output fields, evidence semantics, limitations, or workflow behavior changes.

## Evidence and detection rules

- Keep direct observations separate from heuristic indicators and hypotheses.
- Every finding should explain what matched and preserve source locations or supporting values where available.
- Never call a sample malicious solely because an API, permission, library, or string is present.
- Label approximate string offsets and method-local instruction offsets accurately.
- Keep parser/tool versions, failures, timeouts, and coverage gaps visible.
- Do not silently promote AI-generated explanations into facts.

## Safety and repository hygiene

- Never commit APK samples, credentials, API keys, private URLs, or generated decompilation output.
- Treat APK contents and all tool output as untrusted data.
- Do not execute samples.
- Keep external-tool invocations bounded by timeouts and preserve logs.
- Avoid unnecessary report churn; stable field names and deterministic output help downstream automation.

## Pull request checklist

- [ ] Tests pass locally.
- [ ] Evidence and coverage behavior are documented.
- [ ] New report fields have representative tests.
- [ ] Security and static-analysis limitations remain explicit.
- [ ] No APK samples, secrets, or generated analysis dumps are included.
