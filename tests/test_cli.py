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



def test_dex_coverage_summary_compares_header_and_parsed_class_counts(tmp_path: Path) -> None:
    classes_path = tmp_path / "classes.jsonl"
    classes_path.write_text(
        json.dumps({"dex_index": 0, "class_descriptor": "Lexample/A;"}) + chr(10)
        + json.dumps({"dex_index": 0, "class_descriptor": "Lexample/B;"}) + chr(10)
        + json.dumps({"dex_index": 1, "class_descriptor": "Lexample/C;"}) + chr(10),
        encoding="utf-8",
    )
    dex_rows = [
        {"path": "classes.dex", "class_defs_size": 2},
        {"path": "classes2.dex", "class_defs_size": 2},
    ]

    result = cli._dex_coverage_summary(
        dex_rows,
        {"status": "ok", "dex_objects": 2, "classes": 3},
        classes_path,
    )

    assert result["dex_count_matches_archive"] is True
    assert result["per_dex"][0]["class_count_matches_header"] is True
    assert result["per_dex"][1]["parsed_classes"] == 1
    assert result["per_dex"][1]["class_count_matches_header"] is False
    assert result["class_count_mismatch_count"] == 1


def test_dex_coverage_summary_handles_unavailable_parser_counts(tmp_path: Path) -> None:
    classes_path = tmp_path / "classes.jsonl"
    classes_path.write_text("", encoding="utf-8")

    result = cli._dex_coverage_summary(
        [{"path": "classes.dex", "class_defs_size": 1}],
        {"status": "skipped"},
        classes_path,
    )

    assert result["dex_count_matches_archive"] is None
    assert result["per_dex"][0]["class_count_matches_header"] is None



def test_method_level_evidence_links_api_reference_to_method(tmp_path: Path) -> None:
    instructions = tmp_path / "instructions.jsonl"
    instructions.write_text(
        json.dumps({
            "dex_index": 1,
            "class_descriptor": "Lexample/Loader;",
            "method_name": "loadPlugin",
            "method_descriptor": "()V",
            "opcode": "invoke-virtual",
            "operands": "Ldalvik/system/DexClassLoader;",
            "method_code_offset_bytes": 42,
        }) + "\n"
        + "not valid json\n",
        encoding="utf-8",
    )

    evidence = cli._method_level_evidence(instructions)

    assert len(evidence["dynamic_code_loading"]) == 1
    item = evidence["dynamic_code_loading"][0]
    assert item["class_descriptor"] == "Lexample/Loader;"
    assert item["method_name"] == "loadPlugin"
    assert item["dex_index"] == 1
    assert item["method_code_offset_bytes"] == 42
    assert item["occurrences"] == 1
    assert item["evidence_type"] == "androguard_instruction_api_reference"


def test_method_level_evidence_aggregates_repeated_api_hits_and_keeps_offsets(tmp_path: Path) -> None:
    instructions = tmp_path / "instructions.jsonl"
    base = {
        "dex_index": 0,
        "class_descriptor": "Lexample/Loader;",
        "method_name": "loadPlugin",
        "method_descriptor": "()V",
        "opcode": "invoke-virtual",
        "operands": "Ldalvik/system/DexClassLoader;",
    }
    rows = [
        {**base, "method_code_offset_bytes": 10},
        {**base, "method_code_offset_bytes": 24},
        {**base, "method_code_offset_bytes": 24},
    ]
    instructions.write_text(
        "".join(json.dumps(row) + "\n" for row in rows) + json.dumps(["not", "an", "instruction"]) + "\n",
        encoding="utf-8",
    )

    evidence = cli._method_level_evidence(instructions)["dynamic_code_loading"]

    assert len(evidence) == 1
    assert evidence[0]["method_code_offset_bytes"] == 10
    assert evidence[0]["additional_instruction_offsets_bytes"] == [24]
    assert evidence[0]["occurrences"] == 3


def test_method_level_evidence_is_bounded_and_attached(tmp_path: Path) -> None:
    instructions = tmp_path / "instructions.jsonl"
    rows = [
        {
            "dex_index": 0,
            "class_descriptor": "Lexample/A;",
            "method_name": f"load{i}",
            "method_descriptor": "()V",
            "opcode": "invoke-virtual",
            "operands": "Ldalvik/system/PathClassLoader;",
        }
        for i in range(5)
    ]
    instructions.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    findings = [{"id": "dynamic_code_loading", "evidence": []}]
    cli._attach_method_level_evidence(findings, instructions)

    assert findings[0]["method_evidence_count"] == 5
    assert len(findings[0]["method_evidence"]) == 5
    assert findings[0]["method_evidence"][0]["method_name"] == "load0"

def test_optional_tool_outputs_use_report_root_for_relative_output_dir(tmp_path: Path, monkeypatch) -> None:
    apk = tmp_path / "sample.apk"
    _make_apk(apk, {"AndroidManifest.xml": b"<manifest/>"})
    monkeypatch.chdir(tmp_path)
    calls: list[tuple[str, list[str], Path]] = []

    def fake_run_tool(name, argv, log_dir, **kwargs):
        calls.append((name, argv, log_dir))
        return {"tool": name, "status": "ok"}

    monkeypatch.setattr(cli, "_run_tool", fake_run_tool)
    cli.analyze_apk(
        apk,
        Path("analysis-output"),
        run_optional_tools=True,
        run_androguard=False,
    )

    report_root = (tmp_path / "analysis-output").resolve()
    assert all(log_dir == report_root / "tool-logs" for _, _, log_dir in calls)
    assert calls[0][1][2] == str(report_root / "jadx")
    assert calls[1][1][3] == str(apk.resolve())
    assert calls[1][1][5] == str(report_root / "apktool")
    assert (report_root / "manifest.json").is_file()
    assert not (report_root / "analysis-output").exists()
