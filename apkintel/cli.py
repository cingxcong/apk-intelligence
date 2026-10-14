from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .downloader import DEFAULT_MAX_BYTES, download_apk

MAX_ENTRIES = 100_000
MAX_EXPANDED_BYTES = 1_500_000_000
TEXT_EXTENSIONS = (".xml", ".txt", ".json", ".properties", ".yml", ".yaml", ".html", ".js", ".smali", ".mf", ".cfg", ".ini")
SUSPICIOUS_PATTERNS = [
    ("dynamic_code_loading", re.compile(r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader"), "Dynamic code-loading API reference found."),
    ("reflection", re.compile(r"java/lang/reflect|Class\.forName|Method\.invoke"), "Reflection API reference found."),
    ("native_code", re.compile(r"System\.loadLibrary|System\.load\("), "Native library loading API reference found."),
    ("webview_javascript", re.compile(r"setJavaScriptEnabled|addJavascriptInterface"), "WebView JavaScript configuration/interface reference found."),
    ("crypto_api", re.compile(r"Cipher\.getInstance|SecretKeySpec|MessageDigest"), "Cryptographic API reference found; this is not proof of weak cryptography."),
    ("network_api", re.compile(r"HttpURLConnection|okhttp3|java/net/Socket|URLConnection"), "Network API/library reference found; no network behavior was executed."),
    ("process_execution", re.compile(r"Runtime\.getRuntime|ProcessBuilder"), "Process execution API reference found."),
    ("accessibility_api", re.compile(r"AccessibilityService|BIND_ACCESSIBILITY_SERVICE"), "Accessibility service reference found."),
]


def file_hashes(path: Path) -> dict[str, str]:
    digests = {name: hashlib.new(name) for name in ("sha256", "sha1", "md5")}
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def sha256_file(path: Path) -> str:
    return file_hashes(path)["sha256"]


def tool_version(command: str, args: list[str] | None = None) -> dict[str, Any]:
    executable = shutil.which(command)
    if not executable:
        return {"available": False, "path": None, "version": None}
    try:
        result = subprocess.run([executable, *(args or ["--version"])], capture_output=True, text=True, timeout=15, check=False)
        output = (result.stdout + "\n" + result.stderr).strip()[:1000]
        return {"available": True, "path": executable, "version": output or f"exit={result.returncode}"}
    except Exception as exc:
        return {"available": True, "path": executable, "version": None, "error": str(exc)}


def _jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _run_tool(name: str, argv: list[str], log_dir: Path, timeout: int = 900) -> dict[str, Any]:
    executable = shutil.which(argv[0])
    record: dict[str, Any] = {"tool": name, "available": bool(executable), "command": argv, "status": "skipped"}
    if not executable:
        record["reason"] = "Executable not found on PATH."
        return record
    record["command"] = [executable, *argv[1:]]
    try:
        result = subprocess.run(record["command"], capture_output=True, text=True, timeout=timeout, check=False, cwd=str(log_dir.parent))
        (log_dir / f"{name}.stdout.txt").write_text(result.stdout[-2_000_000:], encoding="utf-8", errors="replace")
        (log_dir / f"{name}.stderr.txt").write_text(result.stderr[-2_000_000:], encoding="utf-8", errors="replace")
        record.update({"status": "ok" if result.returncode == 0 else "error", "exit_code": result.returncode, "stdout_log": f"tool-logs/{name}.stdout.txt", "stderr_log": f"tool-logs/{name}.stderr.txt"})
    except subprocess.TimeoutExpired:
        record.update({"status": "timeout", "timeout_seconds": timeout})
    except Exception as exc:
        record.update({"status": "error", "error": str(exc)})
    return record


def _androguard_extract(apk_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    classes: list[dict[str, Any]] = []
    methods: list[dict[str, Any]] = []
    instructions: list[dict[str, Any]] = []
    references: list[dict[str, Any]] = []
    status: dict[str, Any] = {"available": False, "status": "skipped", "note": "Install a compatible Androguard release to enable structured class/method extraction."}
    try:
        from androguard.misc import AnalyzeAPK  # type: ignore
        status["available"] = True
        try:
            apk_obj, dexes, analysis = AnalyzeAPK(str(apk_path))
            try:
                status["app_metadata"] = {"package_name": apk_obj.get_package(), "version_name": apk_obj.get_androidversion_name(), "version_code": apk_obj.get_androidversion_code(), "permissions": sorted(set(apk_obj.get_permissions() or []))}
            except Exception as meta_exc:
                status["app_metadata_error"] = f"{type(meta_exc).__name__}: {meta_exc}"
            for dex_index, dex in enumerate(dexes):
                for cls in dex.get_classes():
                    descriptor = str(cls.get_name())
                    classes.append({"dex_index": dex_index, "class_descriptor": descriptor, "super_descriptor": str(cls.get_superclassname()) if hasattr(cls, "get_superclassname") else None, "source": "androguard", "evidence": {"archive": apk_path.name, "dex_index": dex_index}})
                    for method in cls.get_methods():
                        method_name = str(method.get_name())
                        method_descriptor = str(method.get_descriptor())
                        method_row: dict[str, Any] = {"dex_index": dex_index, "class_descriptor": descriptor, "name": method_name, "descriptor": method_descriptor, "access_flags": str(method.get_access_flags_string()) if hasattr(method, "get_access_flags_string") else None, "source": "androguard"}
                        try:
                            code = method.get_code()
                            method_row["has_code"] = code is not None
                            if code is not None:
                                code_bytes = None
                                try:
                                    bytecode = code.get_bc()
                                    if hasattr(bytecode, "get_raw"):
                                        code_bytes = bytecode.get_raw()
                                    elif hasattr(bytecode, "get_raw_buff"):
                                        code_bytes = bytecode.get_raw_buff()
                                except Exception:
                                    pass
                                if isinstance(code_bytes, (bytes, bytearray)):
                                    method_row["code_bytes"] = len(code_bytes)
                                    method_row["code_sha256"] = hashlib.sha256(code_bytes).hexdigest()
                                offset = 0
                                count = 0
                                try:
                                    for ins in method.get_instructions():
                                        length = int(ins.get_length()) if hasattr(ins, "get_length") else 0
                                        instructions.append({"dex_index": dex_index, "class_descriptor": descriptor, "method_name": method_name, "method_descriptor": method_descriptor, "method_code_offset_bytes": offset, "opcode": str(ins.get_name()) if hasattr(ins, "get_name") else str(type(ins).__name__), "operands": str(ins.get_output())[:2000] if hasattr(ins, "get_output") else "", "length_bytes": length, "evidence_type": "androguard_instruction"})
                                        offset += max(length, 0)
                                        count += 1
                                except Exception as instruction_exc:
                                    method_row["instruction_extraction_error"] = f"{type(instruction_exc).__name__}: {instruction_exc}"
                                method_row["instruction_count"] = count
                        except Exception as code_exc:
                            method_row["code_extraction_error"] = f"{type(code_exc).__name__}: {code_exc}"
                        methods.append(method_row)
                        try:
                            method_analysis = analysis.get_method(method)
                            if method_analysis is not None and hasattr(method_analysis, "get_xref_to"):
                                for xref in method_analysis.get_xref_to():
                                    target_class = str(xref[0].get_name()) if len(xref) > 0 and hasattr(xref[0], "get_name") else str(xref[0]) if len(xref) > 0 else None
                                    target_method_obj = xref[1] if len(xref) > 1 else None
                                    target_method = None
                                    if target_method_obj is not None:
                                        target_method_obj = target_method_obj.get_method() if hasattr(target_method_obj, "get_method") else target_method_obj
                                        target_method = {"name": str(target_method_obj.get_name()), "descriptor": str(target_method_obj.get_descriptor()), "class_descriptor": str(target_method_obj.get_class_name()) if hasattr(target_method_obj, "get_class_name") else target_class} if hasattr(target_method_obj, "get_name") else str(target_method_obj)
                                    references.append({"dex_index": dex_index, "source_class": descriptor, "source_method": method_name, "source_descriptor": method_descriptor, "target_class": target_class, "target_method": target_method, "reference_kind": "xref_to", "evidence_type": "androguard_cross_reference"})
                        except Exception:
                            pass
            status.update({"status": "ok", "dex_objects": len(dexes), "classes": len(classes), "methods": len(methods)})
        except Exception as exc:
            status.update({"status": "error", "error": f"Androguard parse failed: {type(exc).__name__}: {exc}"})
    except Exception as exc:
        status.update({"status": "unavailable", "error": f"Androguard import failed: {type(exc).__name__}: {exc}"})
    return classes, methods, instructions, references, status


def analyze_apk(apk_path: Path, output_dir: Path, run_optional_tools: bool = True) -> dict[str, Any]:
    apk_path = apk_path.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    log_dir = output_dir / "tool-logs"
    log_dir.mkdir(exist_ok=True)
    if not apk_path.is_file():
        raise FileNotFoundError(f"APK not found: {apk_path}")
    hashes = file_hashes(apk_path)
    sample_sha256 = hashes["sha256"]
    run_started = datetime.now(timezone.utc).isoformat()
    findings: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    dex_rows: list[dict[str, Any]] = []
    string_rows: list[dict[str, Any]] = []
    text_blobs: list[tuple[str, str]] = []
    archive_summary: dict[str, Any] = {"valid_zip": False, "entry_count": 0, "expanded_bytes": 0, "dex_count": 0, "native_libraries": [], "resource_count": 0}
    try:
        with zipfile.ZipFile(apk_path) as archive:
            infos = archive.infolist()
            archive_summary["valid_zip"] = True
            archive_summary["entry_count"] = len(infos)
            if len(infos) > MAX_ENTRIES:
                raise ValueError(f"Archive has too many entries ({len(infos)} > {MAX_ENTRIES}).")
            expanded = sum(max(0, item.file_size) for item in infos)
            archive_summary["expanded_bytes"] = expanded
            if expanded > MAX_EXPANDED_BYTES:
                raise ValueError(f"Archive expands beyond safety limit ({expanded} bytes).")
            for info in infos:
                name = info.filename
                if name.startswith("/") or ".." in Path(name).parts:
                    findings.append({"id": "unsafe_archive_path", "severity": "info", "category": "archive", "claim_type": "observed_fact", "message": "Archive contains a path that looks unsafe when extracted.", "evidence": [{"file": name}], "confidence": "high"})
                    continue
                row = {"path": name, "compressed_bytes": info.compress_size, "uncompressed_bytes": info.file_size, "compression": info.compress_type, "crc32": f"{info.CRC:08x}", "directory": info.is_dir()}
                if not info.is_dir():
                    try:
                        digest = hashlib.sha256()
                        raw = archive.read(info)
                        digest.update(raw)
                        row["sha256"] = digest.hexdigest()
                        if name.endswith(".dex") and (name == "classes.dex" or re.fullmatch(r"classes\d+\.dex", name)):
                            dex_rows.append({"path": name, "sha256": row["sha256"], "bytes": len(raw), "magic": raw[:8].decode("ascii", errors="replace"), "header_checksum_adler32": raw[8:12].hex() if len(raw) >= 12 else None, "header_signature_sha1": raw[12:32].hex() if len(raw) >= 32 else None, "file_size_header": int.from_bytes(raw[32:36], "little") if len(raw) >= 36 else None, "header_size": int.from_bytes(raw[36:40], "little") if len(raw) >= 40 else None, "endian_tag": raw[40:44].hex() if len(raw) >= 44 else None, "string_ids_size": int.from_bytes(raw[56:60], "little") if len(raw) >= 60 else None, "type_ids_size": int.from_bytes(raw[64:68], "little") if len(raw) >= 68 else None, "proto_ids_size": int.from_bytes(raw[72:76], "little") if len(raw) >= 76 else None, "field_ids_size": int.from_bytes(raw[80:84], "little") if len(raw) >= 84 else None, "method_ids_size": int.from_bytes(raw[88:92], "little") if len(raw) >= 92 else None, "class_defs_size": int.from_bytes(raw[96:100], "little") if len(raw) >= 100 else None, "data_size": int.from_bytes(raw[104:108], "little") if len(raw) >= 108 else None, "source": "raw_dex_header", "evidence": {"file": name, "byte_ranges": {"magic": "0x00-0x07", "checksum": "0x08-0x0b", "signature": "0x0c-0x1f", "file_size": "0x20-0x23"}}})
                        if name.endswith(".so") and "/" in name:
                            archive_summary["native_libraries"].append({"path": name, "sha256": row["sha256"], "bytes": len(raw), "elf_magic": raw[:4] == b"\x7fELF"})
                        if name.startswith("res/") or name.startswith("assets/"):
                            archive_summary["resource_count"] += 1
                        if len(raw) <= 2_000_000 and (name.endswith(TEXT_EXTENSIONS) or name.endswith(".dex") or name.endswith(".so")):
                            decoded = raw.decode("utf-8", errors="ignore")
                            text_blobs.append((name, decoded))
                            for match in re.finditer(r"[\x20-\x7e]{5,}", decoded):
                                value = match.group(0).strip()
                                if value:
                                    string_rows.append({"value": value[:2000], "source_file": name, "offset_text_chars_approx": match.start(), "evidence_type": "printable_ascii_sequence", "confidence": "low" if name.endswith(".dex") or name.endswith(".so") else "medium"})
                    except Exception as exc:
                        row["read_error"] = f"{type(exc).__name__}: {exc}"
                files.append(row)
    except zipfile.BadZipFile as exc:
        raise ValueError("Input is not a readable APK/ZIP archive.") from exc

    archive_summary["dex_count"] = len(dex_rows)

    # Keep duplicate strings out of the report while preserving the first source occurrence.
    unique_strings: dict[tuple[str, str], dict[str, Any]] = {}
    for row in string_rows:
        unique_strings.setdefault((row["source_file"], row["value"]), row)
    string_rows = list(unique_strings.values())

    manifest_entry = next((x for x in files if x["path"] == "AndroidManifest.xml"), None)
    if manifest_entry:
        findings.append({"id": "manifest_present", "severity": "info", "category": "manifest", "claim_type": "observed_fact", "message": "AndroidManifest.xml is present in the APK archive.", "evidence": [{"file": "AndroidManifest.xml", "sha256": manifest_entry.get("sha256")}], "confidence": "high"})
    if not dex_rows:
        findings.append({"id": "no_standard_dex_found", "severity": "warning", "category": "coverage", "claim_type": "observed_fact", "message": "No standard classes.dex/classesN.dex entry was found; the APK may be native-only, unusual, packed, or malformed.", "evidence": [{"file": apk_path.name}], "confidence": "medium"})
    if archive_summary["native_libraries"]:
        findings.append({"id": "native_libraries_present", "severity": "info", "category": "native", "claim_type": "observed_fact", "message": "Native shared libraries are included; this initial analyzer fingerprints them but does not fully disassemble them.", "evidence": archive_summary["native_libraries"], "confidence": "high"})

    combined = "\n".join(text for _, text in text_blobs)
    for rule_id, pattern, message in SUSPICIOUS_PATTERNS:
        matches = []
        for source_name, source_text in text_blobs:
            for match in list(pattern.finditer(source_text))[:25]:
                matches.append({"file": source_name, "match": match.group(0)[:200], "offset_text_chars_approx": match.start()})
        if matches:
            findings.append({"id": rule_id, "severity": "info", "category": "behavioral_indicator", "claim_type": "heuristic_indicator", "message": message, "evidence": matches[:100], "confidence": "low", "limitations": "String/pattern presence alone does not establish that the code path is reachable or used."})

    classes, methods, instructions, references, androguard_status = _androguard_extract(apk_path)
    tools: list[dict[str, Any]] = []
    if run_optional_tools:
        jadx_out = output_dir / "jadx"
        apktool_out = output_dir / "apktool"
        if shutil.which("jadx"):
            tools.append(_run_tool("jadx", ["jadx", "-d", str(jadx_out), str(apk_path)], log_dir))
        else:
            tools.append({"tool": "jadx", "available": False, "status": "skipped", "reason": "Install jadx and put it on PATH."})
        if shutil.which("apktool"):
            tools.append(_run_tool("apktool", ["apktool", "d", "-f", str(apk_path), "-o", str(apktool_out)], log_dir))
        else:
            tools.append({"tool": "apktool", "available": False, "status": "skipped", "reason": "Install apktool and put it on PATH."})
        if shutil.which("apkid"):
            tools.append(_run_tool("apkid", ["apkid", str(apk_path)], log_dir, timeout=180))
        else:
            tools.append({"tool": "apkid", "available": False, "status": "skipped", "reason": "Install APKiD and put it on PATH."})

    versions = {"apkintel": __version__, "python": sys.version.split()[0], "androguard": None}
    try:
        versions["androguard"] = importlib.metadata.version("androguard")
    except importlib.metadata.PackageNotFoundError:
        pass
    tool_inventory = {"jadx": tool_version("jadx"), "apktool": tool_version("apktool"), "apkid": tool_version("apkid"), "androguard": {"available": androguard_status.get("available", False), "status": androguard_status.get("status")}}
    manifest = {"schema_version": "1.0", "tool": "APK Intelligence", "tool_version": __version__, "analysis_started_utc": run_started, "analysis_finished_utc": datetime.now(timezone.utc).isoformat(), "sample": {"filename": apk_path.name, "size_bytes": apk_path.stat().st_size, "sha256": sample_sha256, "sha1": hashes["sha1"], "md5": hashes["md5"]}, "archive": archive_summary, "tool_versions": versions, "tool_inventory": tool_inventory, "androguard_extraction": androguard_status, "app_metadata": androguard_status.get("app_metadata"), "optional_tools": tools, "coverage": {"static_only": True, "apk_executed": False, "decompilation_is_lossless": False, "native_analysis": "fingerprints only in initial version", "string_offsets": "approximate character offsets in decoded text, not byte or instruction addresses", "notes": ["Packed/encrypted payloads and runtime-loaded code may not be visible.", "Pattern matches are indicators, not proof of malicious behavior.", "DEX raw-header hashes are exact; class/method inventory depends on optional parser support."]}}

    _jsonl(output_dir / "files.jsonl", files)
    _jsonl(output_dir / "dex.jsonl", dex_rows)
    _jsonl(output_dir / "strings.jsonl", string_rows)
    _jsonl(output_dir / "classes.jsonl", classes)
    _jsonl(output_dir / "methods.jsonl", methods)
    _jsonl(output_dir / "instructions.jsonl", instructions)
    _jsonl(output_dir / "references.jsonl", references)
    (output_dir / "findings.json").write_text(json.dumps({"schema_version": "1.0", "findings": findings}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    counts = Counter(row["category"] for row in findings)
    summary = ["# APK Intelligence Report", "", f"- **Sample:** `{apk_path.name}`", f"- **SHA-256:** `{sample_sha256}`", f"- **Size:** {apk_path.stat().st_size:,} bytes", f"- **DEX files:** {len(dex_rows)}", f"- **Archive entries:** {len(files)}", f"- **Extracted printable strings:** {len(string_rows)}", f"- **Parsed classes / methods:** {len(classes)} / {len(methods)}", f"- **Instructions / cross-references:** {len(instructions)} / {len(references)}", f"- **Static findings:** {len(findings)}", "", "## Finding categories", ""]
    summary.extend([f"- {key}: {value}" for key, value in sorted(counts.items())] or ["- None"])
    summary.extend(["", "## DEX fingerprints", ""])
    summary.extend([f"- `{row['path']}` — SHA-256 `{row['sha256']}`, {row['bytes']:,} bytes, magic `{row['magic']}`" for row in dex_rows] or ["- No standard DEX entries detected."])
    summary.extend(["", "## Evidence and interpretation", "", "Findings distinguish observed facts from heuristic indicators. Pattern matches are not proof of maliciousness, and static analysis cannot reveal all runtime behavior. See `findings.json`, `manifest.json`, and JSONL indexes for machine-readable data.", "", "## Optional tool results", ""])
    summary.extend([f"- {row.get('tool')}: {row.get('status')}" for row in tools] or ["- Optional tools were disabled."])
    (output_dir / "summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="apkintel", description="Evidence-first static APK analysis and DEX fingerprinting.")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="Analyze a local APK without executing it.")
    analyze.add_argument("apk", type=Path)
    analyze.add_argument("--out", type=Path, default=Path("analysis-output"))
    analyze.add_argument("--no-optional-tools", action="store_true", help="Skip JADX/Apktool/APKiD subprocesses.")
    fetch = sub.add_parser("analyze-url", help="Safely download an HTTPS APK URL and analyze it.")
    fetch.add_argument("url")
    fetch.add_argument("--out", type=Path, default=Path("analysis-output"))
    fetch.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    fetch.add_argument("--no-optional-tools", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "analyze-url":
            sample_dir = args.out / "input"
            sample_dir.mkdir(parents=True, exist_ok=True)
            apk_path = download_apk(args.url, sample_dir / "sample.apk", args.max_bytes)
        else:
            apk_path = args.apk
        manifest = analyze_apk(apk_path, args.out, run_optional_tools=not args.no_optional_tools)
        print(json.dumps({"status": "ok", "output_dir": str(args.out.resolve()), "sha256": manifest["sample"]["sha256"], "dex_count": manifest["archive"]["dex_count"], "report": str((args.out / 'summary.md').resolve())}, indent=2))
        return 0
    except Exception as exc:
        print(f"apkintel: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
