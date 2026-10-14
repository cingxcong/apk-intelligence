# Contributing

1. Create a focused branch and add tests for new report fields or detection rules.
2. Keep deterministic evidence separate from heuristics and model-generated hypotheses.
3. Never add APK samples, credentials, API keys, private URLs, or generated decompilation output to Git.
4. Treat APK contents and tool output as untrusted input. Do not execute samples.
5. Keep external-tool invocations bounded by timeouts and capture errors as coverage gaps.
6. Run tests with `python -m unittest discover -s tests -v` before opening a pull request.

Detection rules should explain what they match, include source locations, and avoid calling a sample malicious solely from API-name or string presence.
