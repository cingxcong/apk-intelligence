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



def test_parse_method_reference_from_invoke_operands() -> None:
    parsed = cli._parse_method_reference(
        "v0, Lcom/example/PluginLoader;->loadPlugin(Ljava/lang/String;)V"
    )

    assert parsed == {
        "target_class_descriptor": "Lcom/example/PluginLoader;",
        "target_method_name": "loadPlugin",
        "target_method_descriptor": "(Ljava/lang/String;)V",
    }


def test_parse_method_reference_ignores_non_method_operands() -> None:
    assert cli._parse_method_reference("v0, v1") is None
    assert cli._parse_method_reference("Lcom/example/Plugin;->field:Ljava/lang/String;") is None

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
            "operands": "v0, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/ClassLoader;)V",
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
    assert item["target_class_descriptor"] == "Ldalvik/system/DexClassLoader;"
    assert item["target_method_name"] == "<init>"
    assert item["target_method_descriptor"] == "(Ljava/lang/ClassLoader;)V"
    assert item["target_resolution"] == "symbolic_target_only"


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


def test_method_level_evidence_skips_rows_without_method_identity(tmp_path: Path) -> None:
    instructions = tmp_path / "instructions.jsonl"
    rows = [
        {"opcode": "invoke-virtual", "operands": "Ldalvik/system/DexClassLoader;"},
        {"opcode": "invoke-virtual", "operands": "Ldalvik/system/PathClassLoader;"},
        {
            "dex_index": 0,
            "class_descriptor": "Lexample/Loader;",
            "method_name": "loadPlugin",
            "method_descriptor": "()V",
            "opcode": "invoke-virtual",
            "operands": "Ldalvik/system/DexClassLoader;",
        },
    ]
    instructions.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    evidence = cli._method_level_evidence(instructions)["dynamic_code_loading"]

    assert len(evidence) == 1
    assert evidence[0]["class_descriptor"] == "Lexample/Loader;"
    assert evidence[0]["occurrences"] == 1


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


def test_optional_tool_failure_is_reported_as_coverage_warning(tmp_path: Path, monkeypatch) -> None:
    apk = tmp_path / "sample.apk"
    _make_apk(apk, {"AndroidManifest.xml": b"<manifest/>"})
    output = tmp_path / "out"

    def fake_run_tool(name, argv, log_dir, **kwargs):
        if name == "jadx":
            (log_dir / "jadx.stderr.txt").write_text("decoder failed: unsupported instruction", encoding="utf-8")
            (log_dir / "jadx.stdout.txt").write_text("partial output retained", encoding="utf-8")
            return {
                "tool": name,
                "status": "error",
                "exit_code": 3,
                "stderr_log": "tool-logs/jadx.stderr.txt",
                "stdout_log": "tool-logs/jadx.stdout.txt",
            }
        return {"tool": name, "status": "ok"}

    monkeypatch.setattr(cli, "_run_tool", fake_run_tool)
    cli.analyze_apk(apk, output, run_optional_tools=True, run_androguard=False)

    findings = _findings(output)
    failure = next(item for item in findings if item["id"] == "optional_tool_failures")
    assert failure["severity"] == "warning"
    assert failure["category"] == "coverage"
    assert failure["evidence"][0]["tool"] == "jadx"
    assert failure["evidence"][0]["exit_code"] == 3
    assert "unsupported instruction" in failure["evidence"][0]["stderr_tail"]
    assert "partial output retained" in failure["evidence"][0]["stdout_tail"]


def test_tool_version_uses_package_metadata_when_requested(monkeypatch) -> None:
    monkeypatch.setattr(cli.shutil, "which", lambda command: "/usr/bin/apkid")
    monkeypatch.setattr(cli.importlib.metadata, "version", lambda distribution: "3.3.0")

    result = cli.tool_version("apkid", distribution="apkid")

    assert result == {
        "available": True,
        "path": "/usr/bin/apkid",
        "version": "3.3.0",
    }


def test_tool_version_does_not_report_failed_probe_as_version(monkeypatch) -> None:
    class Result:
        stdout = ""
        stderr = "unrecognized arguments: --version"
        returncode = 2

    monkeypatch.setattr(cli.shutil, "which", lambda command: "/usr/bin/tool")
    monkeypatch.setattr(cli.subprocess, "run", lambda *args, **kwargs: Result())

    result = cli.tool_version("tool")

    assert result["available"] is True
    assert result["version"] is None
    assert result["version_probe_exit_code"] == 2
    assert "unrecognized arguments" in result["version_probe_output"]


def test_androguard_parse_failure_is_reported_as_coverage_warning(tmp_path: Path, monkeypatch) -> None:
    apk = tmp_path / "sample.apk"
    _make_apk(apk, {"classes.dex": b"dex\n035\x00" + b"\x00" * 112})
    output = tmp_path / "out"

    def fake_extract(apk_path, output_dir, max_methods=100_000):
        for filename in ("classes.jsonl", "methods.jsonl", "instructions.jsonl", "references.jsonl"):
            (output_dir / filename).write_text("", encoding="utf-8")
        return {
            "available": True,
            "status": "error",
            "error": "Androguard parse failed: ValueError: malformed DEX",
            "max_methods": max_methods,
        }

    monkeypatch.setattr(cli, "_androguard_extract", fake_extract)
    cli.analyze_apk(apk, output, run_optional_tools=False, run_androguard=True)

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["androguard_extraction"]["status"] == "error"
    assert any(
        warning["kind"] == "androguard_extraction_incomplete"
        and warning["status"] == "error"
        for warning in manifest["coverage"]["coverage_warnings"]
    )
    findings = _findings(output)
    coverage = next(item for item in findings if item["id"] == "dex_inventory_coverage_mismatch")
    assert coverage["severity"] == "warning"
    assert any(item["kind"] == "androguard_extraction_incomplete" for item in coverage["evidence"])



def test_method_coverage_summary_surfaces_per_method_extraction_errors(tmp_path: Path) -> None:
    methods = tmp_path / "methods.jsonl"
    methods.write_text(
        json.dumps({
            "dex_index": 2,
            "class_descriptor": "Lexample/Broken;",
            "name": "decode",
            "descriptor": "()V",
            "has_code": True,
            "instruction_count": 0,
            "instruction_extraction_error": "ValueError: unsupported opcode",
        }) + "\n"
        + json.dumps({
            "dex_index": 0,
            "class_descriptor": "Lexample/NoCode;",
            "name": "stub",
            "descriptor": "()V",
            "has_code": False,
        }) + "\n",
        encoding="utf-8",
    )

    coverage = cli._method_coverage_summary(methods)

    assert coverage["ledger_available"] is True
    assert coverage["methods_emitted"] == 2
    assert coverage["methods_with_code"] == 1
    assert coverage["methods_without_code"] == 1
    assert coverage["instruction_extraction_errors"] == 1
    assert coverage["code_extraction_errors"] == 0
    assert coverage["method_errors_total"] == 1
    assert coverage["error_examples"][0]["class_descriptor"] == "Lexample/Broken;"


def test_log_diagnostics_counts_and_bounds_error_examples(tmp_path: Path) -> None:
    log = tmp_path / "jadx.stdout.txt"
    log.write_text(
        "INFO - starting\nERROR - method failed\n"
        + "".join(f"Exception: failure {index}\n" for index in range(40)),
        encoding="utf-8",
    )

    diagnostics = cli._log_diagnostics(log, max_examples=5)

    assert diagnostics["bytes"] == log.stat().st_size
    assert diagnostics["matching_line_count"] == 41
    assert len(diagnostics["examples"]) == 5
    assert diagnostics["examples"][0]["line"] == 2


def test_run_tool_records_jadx_reported_error_count_and_duration(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cli.shutil, "which", lambda command: "/usr/bin/jadx")

    class Result:
        returncode = 3

    def fake_run(command, stdout, stderr, **kwargs):
        stdout.write("ERROR - finished with errors, count: 259\n")
        stderr.write("decoder exception\n")
        return Result()

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    logs = tmp_path / "tool-logs"
    logs.mkdir()

    result = cli._run_tool("jadx", ["jadx", "-d", "out", "sample.apk"], logs)

    assert result["status"] == "error"
    assert result["exit_code"] == 3
    assert result["reported_decompilation_error_count"] == 259
    assert result["duration_seconds"] >= 0
    assert result["log_diagnostics"]["stdout"]["matching_line_count"] == 1
    assert result["log_diagnostics"]["stderr"]["matching_line_count"] == 1

def test_string_truncation_is_in_coverage_warnings(tmp_path: Path, monkeypatch) -> None:
    apk = tmp_path / "strings.apk"
    _make_apk(apk, {"assets/strings.txt": b"alpha_string\nsecond_string\nthird_string\n"})
    output = tmp_path / "out"
    monkeypatch.setattr(cli, "MAX_STRING_ROWS", 1)

    cli.analyze_apk(apk, output, run_optional_tools=False, run_androguard=False)

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    warnings = manifest["coverage"]["coverage_warnings"]
    warning = next(item for item in warnings if item["kind"] == "printable_string_output_truncated")
    assert warning["limit"] == 1
    assert warning["affected_files"] == ["assets/strings.txt"]
    assert manifest["coverage"]["strings_truncated"] is True
    assert any(item["id"] == "analysis_coverage_limited" for item in _findings(output))


def test_reference_truncation_is_in_coverage_warnings(tmp_path: Path, monkeypatch) -> None:
    apk = tmp_path / "references.apk"
    _make_apk(apk, {"classes.dex": b"dex\\n035\\x00" + b"\\x00" * 112})
    output = tmp_path / "out"

    def fake_extract(apk_path, output_dir, max_methods=100_000):
        for filename in ("classes.jsonl", "methods.jsonl", "instructions.jsonl", "references.jsonl"):
            (output_dir / filename).write_text("", encoding="utf-8")
        return {
            "available": True, "status": "ok", "classes": 0, "methods": 0,
            "instructions": 0, "references": 200_000, "references_truncated": True,
            "reference_note": "Reference output reached the row cap.",
            "dex_count": 1, "truncated": False, "max_methods": max_methods,
        }

    monkeypatch.setattr(cli, "_androguard_extract", fake_extract)
    cli.analyze_apk(apk, output, run_optional_tools=False, run_androguard=True)

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    warning = next(item for item in manifest["coverage"]["coverage_warnings"] if item["kind"] == "reference_output_truncated")
    assert warning["emitted_reference_rows"] == 200_000
    assert warning["limit"] == cli.MAX_REFERENCE_ROWS
    assert warning["note"] == "Reference output reached the row cap."
    finding = next(item for item in _findings(output) if item["id"] == "dex_inventory_coverage_mismatch")
    assert any(item["kind"] == "reference_output_truncated" for item in finding["evidence"])

def test_resource_coverage_distinguishes_inventory_from_semantic_decoding() -> None:
    summary = cli._resource_coverage_summary([
        {"path": "res/layout/main.xml", "directory": False, "sha256": "abc", "uncompressed_bytes": 100, "bytes_read": 100},
        {"path": "res/drawable/icon.png", "directory": False, "sha256": "def", "uncompressed_bytes": 250, "bytes_read": 250},
        {"path": "assets/fonts/app.ttf", "directory": False, "sha256": "ghi", "uncompressed_bytes": 400, "bytes_read": 300},
        {"path": "assets/sound.mp3", "directory": False, "read_error": "IOError", "uncompressed_bytes": 500},
        {"path": "res/layout", "directory": True, "uncompressed_bytes": 0},
    ])

    assert summary["inventory_count"] == 4
    assert summary["hashed_count"] == 3
    assert summary["read_error_count"] == 1
    assert summary["incomplete_read_count"] == 1
    assert summary["uncompressed_bytes_total"] == 1250
    assert summary["by_type"] == {"xml": 1, "images": 1, "fonts": 1, "media": 1, "layouts": 1}
    assert summary["semantic_decoding"].startswith("not_claimed;")



def test_optional_tools_run_concurrently_and_keep_deterministic_order(tmp_path: Path, monkeypatch) -> None:
    apk = tmp_path / "sample.apk"
    _make_apk(apk, {"AndroidManifest.xml": b"<manifest/>"})
    started: list[str] = []

    def fake_run_tool(name, argv, log_dir, **kwargs):
        started.append(name)
        return {"tool": name, "status": "ok"}

    monkeypatch.setattr(cli, "_run_tool", fake_run_tool)
    manifest = cli.analyze_apk(
        apk,
        tmp_path / "out",
        run_optional_tools=True,
        run_androguard=False,
    )

    assert sorted(started) == ["apkid", "apktool", "jadx"]
    assert [row["tool"] for row in manifest["optional_tools"]] == ["jadx", "apktool", "apkid"]
