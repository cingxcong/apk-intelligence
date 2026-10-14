from __future__ import annotations

import json
import zipfile
from pathlib import Path

from apkintel import cli


def _make_apk(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return path


def _findings(output: Path) -> list[dict]:
    return json.loads((output / "findings.json").read_text(encoding="utf-8"))["findings"]


def test_large_dex_is_scanned_for_patterns_and_strings(tmp_path: Path) -> None:
    apk = tmp_path / "large.apk"
    # Place the marker across the chunk boundary to exercise overlap handling.
    payload = bytearray(b"\x00" * (3 * 1024 * 1024))
    marker = b"DexClassLoader"
    start = cli.SCAN_CHUNK_BYTES - 5
    payload[start:start + len(marker)] = marker
    _make_apk(apk, {"classes.dex": bytes(payload)})
    output = tmp_path / "out"

    cli.analyze_apk(apk, output, run_optional_tools=False, run_androguard=False)

    findings = _findings(output)
    assert any(item["id"] == "dynamic_code_loading" for item in findings)
    strings = [json.loads(line) for line in (output / "strings.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any("DexClassLoader" in item["value"] for item in strings)
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["archive"]["dex_count"] == 1
    assert manifest["coverage"]["apk_executed"] is False


def test_skipped_unsafe_file_is_noted_in_findings_and_manifest(tmp_path: Path) -> None:
    apk = tmp_path / "unsafe.apk"
    _make_apk(apk, {"../outside.txt": b"DexClassLoader", "AndroidManifest.xml": b"<manifest/>"})
    output = tmp_path / "out"

    cli.analyze_apk(apk, output, run_optional_tools=False, run_androguard=False)

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    findings = _findings(output)
    assert any(row["file"] == "../outside.txt" for row in manifest["coverage"]["skipped_or_truncated_files"])
    assert any(item["id"] == "analysis_coverage_limited" for item in findings)


def test_analyze_url_flags_are_forwarded(tmp_path: Path, monkeypatch, capsys) -> None:
    downloaded = tmp_path / "fake.apk"
    calls: dict = {}

    def fake_download(url, destination, max_bytes):
        calls["download"] = (url, destination, max_bytes)
        return downloaded

    def fake_analyze(path, out, **kwargs):
        calls["analyze"] = (path, out, kwargs)
        return {"sample": {"sha256": "test-sha"}, "archive": {"dex_count": 0}}

    monkeypatch.setattr(cli, "download_apk", fake_download)
    monkeypatch.setattr(cli, "analyze_apk", fake_analyze)
    result = cli.main([
        "analyze-url", "https://example.com/sample.apk",
        "--out", str(tmp_path / "out"),
        "--max-bytes", "12345",
        "--no-optional-tools", "--no-androguard", "--max-methods", "7",
    ])

    assert result == 0
    assert calls["download"][2] == 12345
    assert calls["analyze"][2] == {
        "run_optional_tools": False,
        "run_androguard": False,
        "max_methods": 7,
    }
    assert json.loads(capsys.readouterr().out)["status"] == "ok"


def test_max_methods_zero_means_unlimited_and_negative_is_rejected(tmp_path: Path, monkeypatch) -> None:
    downloaded = tmp_path / "fake.apk"
    monkeypatch.setattr(cli, "download_apk", lambda *args, **kwargs: downloaded)
    seen: dict = {}

    def fake_analyze(path, out, **kwargs):
        seen.update(kwargs)
        return {"sample": {"sha256": "x"}, "archive": {"dex_count": 0}}

    monkeypatch.setattr(cli, "analyze_apk", fake_analyze)
    assert cli.main(["analyze-url", "https://example.com/a.apk", "--out", str(tmp_path / "out"), "--max-methods", "0"]) == 0
    assert seen["max_methods"] is None
    assert cli.main(["analyze-url", "https://example.com/a.apk", "--out", str(tmp_path / "out"), "--max-methods", "-1"]) == 2

def test_require_androguard_returns_nonzero_when_extraction_fails(tmp_path: Path, monkeypatch, capsys) -> None:
    downloaded = tmp_path / "fake.apk"
    monkeypatch.setattr(cli, "download_apk", lambda *args, **kwargs: downloaded)
    monkeypatch.setattr(cli, "analyze_apk", lambda *args, **kwargs: {
        "sample": {"sha256": "x"},
        "archive": {"dex_count": 1},
        "androguard_extraction": {"status": "error", "error": "simulated parser failure"},
    })

    result = cli.main([
        "analyze-url", "https://example.com/a.apk",
        "--out", str(tmp_path / "out"),
        "--require-androguard",
    ])

    assert result == 3
    assert "Androguard was required" in capsys.readouterr().err
