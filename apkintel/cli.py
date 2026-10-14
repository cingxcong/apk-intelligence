from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import logging
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
SCAN_CHUNK_BYTES = 1024 * 1024
SCAN_OVERLAP_BYTES = 512
_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]+")
MAX_STRING_ROWS = 200_000
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
        for chunk in iter(lambda: handle.read(SCAN_CHUNK_BYTES), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


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


class _JsonlWriter:
    def __init__(self, path: Path) -> None:
        self.handle = path.open("w", encoding="utf-8")
        self.count = 0

    def write(self, row: dict[str, Any]) -> None:
        self.handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        self.count += 1

    def close(self) -> None:
        self.handle.close()


def _scan_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo, collect_strings: bool, max_strings: int = MAX_STRING_ROWS) -> dict[str, Any]:
    """Hash and scan ZIP members incrementally, retaining overlap for boundary matches."""
    digest = hashlib.sha256()
    prefix = bytearray()
    strings: list[dict[str, Any]] = []
    hits: dict[str, list[dict[str, Any]]] = {rule_id: [] for rule_id, _, _ in SUSPICIOUS_PATTERNS}
    seen_offsets: dict[str, set[int]] = {rule_id: set() for rule_id, _, _ in SUSPICIOUS_PATTERNS}
    overlap = b""
    carry = bytearray()
    carry_start = 0
    total = 0
    strings_truncated = False
    overlap_size = max(SCAN_OVERLAP_BYTES, max(len(p.pattern) for _, p, _ in SUSPICIOUS_PATTERNS) * 2)
    next_progress = 64 * 1024 * 1024

    def emit_string(value: bytes, offset: int) -> None:
        nonlocal strings_truncated
        if len(value) < 5:
            return
        if len(strings) >= max_strings:
            strings_truncated = True
            return
        strings.append({
            "value": value[:2000].decode("ascii", errors="ignore"),
            "source_file": info.filename,
            "offset_text_chars_approx": offset,
            "evidence_type": "printable_ascii_sequence",
            "confidence": "low" if info.filename.endswith((".dex", ".so")) else "medium",
        })

    with archive.open(info, "r") as member:
        while True:
            chunk = member.read(SCAN_CHUNK_BYTES)
            if not chunk:
                break
            chunk_start = total
            total += len(chunk)
            digest.update(chunk)
            if len(prefix) < 112:
                prefix.extend(chunk[:112 - len(prefix)])

            combined = overlap + chunk
            combined_base = chunk_start - len(overlap)
            text = combined.decode("latin-1")
            for rule_id, pattern, _ in SUSPICIOUS_PATTERNS:
                for match in pattern.finditer(text):
                    offset = combined_base + match.start()
                    # Overlap catches split matches; offsets and evidence are bounded to avoid match floods.
                    if offset in seen_offsets[rule_id]:
                        continue
                    if len(hits[rule_id]) >= 100:
                        break
                    seen_offsets[rule_id].add(offset)
                    hits[rule_id].append({"file": info.filename, "match": match.group(0)[:200], "offset_text_chars_approx": offset})

            if collect_strings:
                # Regex runs in optimized bytecode rather than iterating in Python over every byte.
                # Keep only the start of a long run across chunks; emitted string values are capped at 2,000 bytes.
                match_iter = iter(_PRINTABLE_RUN_RE.finditer(chunk))
                first_match = next(match_iter, None)
                skip_first = False
                if carry:
                    if first_match is not None and first_match.start() == 0:
                        leading = first_match
                        room = max(0, 2000 - len(carry))
                        if room:
                            carry.extend(chunk[:min(leading.end(), room)])
                        # If the run reaches chunk end, retain it for the next chunk.
                        # Otherwise it has ended and the saved prefix can be emitted.
                        if leading.end() < len(chunk):
                            emit_string(bytes(carry), carry_start)
                            carry.clear()
                        skip_first = True
                    else:
                        # The previous chunk's trailing run ended at this chunk boundary.
                        emit_string(bytes(carry), carry_start)
                        carry.clear()

                def process_match(match: re.Match[bytes]) -> None:
                    nonlocal carry_start, carry
                    run = match.group()
                    if match.end() == len(chunk):
                        carry_start = chunk_start + match.start()
                        carry = bytearray(run[:2000])
                    elif len(run) >= 5:
                        emit_string(run[:2000], chunk_start + match.start())

                if first_match is not None and not skip_first:
                    process_match(first_match)
                for match in match_iter:
                    process_match(match)

            overlap = combined[-overlap_size:]
            if total >= next_progress:
                print(f"[apkintel] Scanning {info.filename}: {total:,}/{info.file_size:,} bytes", file=sys.stderr, flush=True)
                next_progress = total + 64 * 1024 * 1024

    if collect_strings and carry:
        emit_string(bytes(carry), carry_start)
    return {"sha256": digest.hexdigest(), "bytes_read": total, "prefix": bytes(prefix), "strings": strings, "strings_truncated": strings_truncated, "pattern_hits": hits}

def _run_tool(name: str, argv: list[str], log_dir: Path, timeout: int = 900, java_opts: str | None = None) -> dict[str, Any]:
    executable = shutil.which(argv[0])
    record: dict[str, Any] = {"tool": name, "available": bool(executable), "command": argv, "status": "skipped", "timeout_seconds": timeout}
    if not executable:
        record["reason"] = "Executable not found on PATH."
        return record
    command = [executable, *argv[1:]]
    if java_opts and name in {"jadx", "apktool"}:
        import os
        env = dict(os.environ)
        env["JAVA_TOOL_OPTIONS"] = java_opts
    else:
        env = None
    record["command"] = command
    stdout_path = log_dir / f"{name}.stdout.txt"
    stderr_path = log_dir / f"{name}.stderr.txt"
    try:
        # Stream tool output to disk rather than retaining potentially huge logs in RAM.
        with stdout_path.open("w", encoding="utf-8", errors="replace") as stdout_handle, stderr_path.open("w", encoding="utf-8", errors="replace") as stderr_handle:
            result = subprocess.run(command, stdout=stdout_handle, stderr=stderr_handle, text=True, timeout=timeout, check=False, cwd=str(log_dir.parent), env=env)
        record.update({"status": "ok" if result.returncode == 0 else "error", "exit_code": result.returncode, "stdout_log": f"tool-logs/{name}.stdout.txt", "stderr_log": f"tool-logs/{name}.stderr.txt"})
    except subprocess.TimeoutExpired:
        record.update({"status": "timeout", "reason": "Tool exceeded configured timeout.", "stdout_log": f"tool-logs/{name}.stdout.txt", "stderr_log": f"tool-logs/{name}.stderr.txt"})
    except Exception as exc:
        record.update({"status": "error", "error": str(exc)})
    return record


def _androguard_extract(apk_path: Path, output_dir: Path, max_methods: int | None = 100_000) -> dict[str, Any]:
    """Stream Androguard records to JSONL instead of accumulating result lists."""
    status: dict[str, Any] = {"available": False, "status": "skipped", "note": "Install a compatible Androguard release to enable structured class/method extraction.", "max_methods": max_methods}
    writers = {name: _JsonlWriter(output_dir / f"{name}.jsonl") for name in ("classes", "methods", "instructions", "references")}
    previous_disable = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        try:
            from loguru import logger as loguru_logger  # type: ignore
            loguru_logger.disable("androguard")
        except Exception:
            pass
        try:
            from androguard.core.apk import APK  # type: ignore
            from androguard.core.dex import DEX  # type: ignore
            status["available"] = True
            print("[apkintel] Androguard parsing started; using DEX inventory mode (cross-reference graph disabled for performance).", file=sys.stderr, flush=True)
            apk_obj = APK(str(apk_path))
            # Androguard 4.1.x exposes get_all_dex() as a generator.
            # Materialize it once so progress reporting can safely use len().
            dex_payloads = list(apk_obj.get_all_dex())
            dexes = []
            for dex_index, dex_payload in enumerate(dex_payloads):
                print(f"[apkintel] Androguard: parsing DEX {dex_index + 1}/{len(dex_payloads)} ({len(dex_payload):,} bytes).", file=sys.stderr, flush=True)
                dex = DEX(dex_payload)
                dexes.append(dex)
            print(f"[apkintel] Androguard: DEX parsing complete ({len(dexes)} DEX file(s)); extracting classes and methods.", file=sys.stderr, flush=True)
            status["cross_references"] = "disabled_for_performance"
            try:
                status["app_metadata"] = {"package_name": apk_obj.get_package(), "version_name": apk_obj.get_androidversion_name(), "version_code": apk_obj.get_androidversion_code(), "permissions": sorted(set(apk_obj.get_permissions() or []))}
            except Exception as exc:
                status["app_metadata_error"] = f"{type(exc).__name__}: {exc}"
            methods_seen = 0
            truncated = False
            for dex_index, dex in enumerate(dexes):
                for cls in dex.get_classes():
                    descriptor = str(cls.get_name())
                    writers["classes"].write({"dex_index": dex_index, "class_descriptor": descriptor, "super_descriptor": str(cls.get_superclassname()) if hasattr(cls, "get_superclassname") else None, "source": "androguard", "evidence": {"archive": apk_path.name, "dex_index": dex_index}})
                    for method in cls.get_methods():
                        if max_methods is not None and methods_seen >= max_methods:
                            truncated = True
                            break
                        methods_seen += 1
                        method_name, method_descriptor = str(method.get_name()), str(method.get_descriptor())
                        row: dict[str, Any] = {"dex_index": dex_index, "class_descriptor": descriptor, "name": method_name, "descriptor": method_descriptor, "access_flags": str(method.get_access_flags_string()) if hasattr(method, "get_access_flags_string") else None, "source": "androguard"}
                        try:
                            code = method.get_code()
                            row["has_code"] = code is not None
                            if code is not None:
                                try:
                                    bytecode = code.get_bc()
                                    code_bytes = bytecode.get_raw() if hasattr(bytecode, "get_raw") else bytecode.get_raw_buff() if hasattr(bytecode, "get_raw_buff") else None
                                    if isinstance(code_bytes, (bytes, bytearray)):
                                        row["code_bytes"] = len(code_bytes)
                                        row["code_sha256"] = hashlib.sha256(code_bytes).hexdigest()
                                except Exception:
                                    pass
                                offset = count = 0
                                try:
                                    for ins in method.get_instructions():
                                        length = int(ins.get_length()) if hasattr(ins, "get_length") else 0
                                        writers["instructions"].write({"dex_index": dex_index, "class_descriptor": descriptor, "method_name": method_name, "method_descriptor": method_descriptor, "method_code_offset_bytes": offset, "opcode": str(ins.get_name()) if hasattr(ins, "get_name") else type(ins).__name__, "operands": str(ins.get_output())[:2000] if hasattr(ins, "get_output") else "", "length_bytes": length, "evidence_type": "androguard_instruction"})
                                        offset += max(0, length)
                                        count += 1
                                except Exception as exc:
                                    row["instruction_extraction_error"] = f"{type(exc).__name__}: {exc}"
                                row["instruction_count"] = count
                        except Exception as exc:
                            row["code_extraction_error"] = f"{type(exc).__name__}: {exc}"
                        writers["methods"].write(row)
            status.update({"status": "ok", "dex_objects": len(dexes), "classes": writers["classes"].count, "methods": writers["methods"].count, "instructions": writers["instructions"].count, "references": writers["references"].count, "truncated": truncated, "cross_references": "disabled_for_performance"})
            if truncated:
                status["note"] = f"Class inventory completed; method and instruction output truncated at --max-methods={max_methods}. Remaining methods and instructions were not emitted."
        except Exception as exc:
            status.update({"status": "error", "error": f"Androguard parse failed: {type(exc).__name__}: {exc}"})
    except Exception as exc:
        status.update({"status": "unavailable", "error": f"Androguard import failed: {type(exc).__name__}: {exc}"})
    finally:
        for writer in writers.values():
            writer.close()
        logging.disable(previous_disable)
    return status



def _dex_coverage_summary(dex_rows: list[dict[str, Any]], androguard_status: dict[str, Any], classes_path: Path) -> dict[str, Any]:
    """Compare raw DEX header class counts with the classes actually emitted by Androguard."""
    parsed_by_dex: Counter[int] = Counter()
    if classes_path.is_file():
        with classes_path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                    parsed_by_dex[int(row["dex_index"])] += 1
                except (ValueError, KeyError, TypeError):
                    continue

    dex_details = []
    for dex_index, dex_row in enumerate(dex_rows):
        expected = dex_row.get("class_defs_size")
        parsed = parsed_by_dex.get(dex_index, 0)
        dex_details.append({
            "dex_index": dex_index,
            "path": dex_row["path"],
            "header_class_defs": expected,
            "parsed_classes": parsed,
            "class_count_comparable": isinstance(expected, int) and androguard_status.get("status") == "ok",
            "class_count_matches_header": parsed == expected if isinstance(expected, int) and androguard_status.get("status") == "ok" else None,
        })
    expected_dex_count = len(dex_rows)
    parsed_dex_count = androguard_status.get("dex_objects")
    dex_count_matches = parsed_dex_count == expected_dex_count if isinstance(parsed_dex_count, int) else None
    class_mismatches = [item for item in dex_details if item["class_count_matches_header"] is False]
    return {
        "archive_dex_count": expected_dex_count,
        "androguard_dex_count": parsed_dex_count,
        "dex_count_matches_archive": dex_count_matches,
        "per_dex": dex_details,
        "class_count_mismatch_count": len(class_mismatches),
        "class_counts_match_headers": all(item["class_count_matches_header"] is not False for item in dex_details),
        "limitations": "DEX header counts are a comparison baseline, not proof that every class is semantically valid or fully analyzed.",
    }



_METHOD_EVIDENCE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("dynamic_code_loading", re.compile(r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader")),
    ("reflection", re.compile(r"java/lang/reflect|Class\.forName|Method\.invoke")),
    ("native_code", re.compile(r"System\.loadLibrary|System\.load\\(")),
    ("webview_javascript", re.compile(r"setJavaScriptEnabled|addJavascriptInterface")),
    ("crypto_api", re.compile(r"Cipher;?\.getInstance|SecretKeySpec|MessageDigest")),
    ("network_api", re.compile(r"HttpURLConnection|okhttp3|java/net/Socket|URLConnection")),
    ("process_execution", re.compile(r"Runtime;?\.getRuntime|ProcessBuilder")),
    ("accessibility_api", re.compile(r"AccessibilityService|BIND_ACCESSIBILITY_SERVICE")),
]


def _method_level_evidence(instructions_path: Path, limit_per_rule: int = 100) -> dict[str, list[dict[str, Any]]]:
    """Link API-pattern indicators to the class and method containing an instruction."""
    evidence: dict[str, list[dict[str, Any]]] = {rule_id: [] for rule_id, _ in _METHOD_EVIDENCE_PATTERNS}
    if not instructions_path.is_file():
        return evidence
    with instructions_path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            searchable = " ".join(str(row.get(key) or "") for key in ("operands", "opcode"))
            if not searchable.strip():
                continue
            for rule_id, pattern in _METHOD_EVIDENCE_PATTERNS:
                if len(evidence[rule_id]) >= limit_per_rule or not pattern.search(searchable):
                    continue
                evidence[rule_id].append({
                    "dex_index": row.get("dex_index"),
                    "class_descriptor": row.get("class_descriptor"),
                    "method_name": row.get("method_name"),
                    "method_descriptor": row.get("method_descriptor"),
                    "opcode": row.get("opcode"),
                    "operands": str(row.get("operands") or "")[:500],
                    "evidence_type": "androguard_instruction_api_reference",
                })
    return evidence


def _attach_method_level_evidence(findings: list[dict[str, Any]], instructions_path: Path) -> None:
    """Attach bounded, method-attributed evidence without treating API use as proof of malice."""
    for rule_id, rows in _method_level_evidence(instructions_path).items():
        if not rows:
            continue
        finding = next((item for item in findings if item.get("id") == rule_id), None)
        if finding is None:
            finding = {
                "id": rule_id,
                "severity": "info",
                "category": "behavioral_indicator",
                "claim_type": "heuristic_indicator",
                "message": "An API reference was observed in parsed method instructions.",
                "evidence": [],
                "confidence": "low",
                "limitations": "An API reference does not establish that the code path is reachable or malicious.",
            }
            findings.append(finding)
        finding["method_evidence"] = rows
        finding["method_evidence_count"] = len(rows)

def analyze_apk(apk_path: Path, output_dir: Path, run_optional_tools: bool = True, run_androguard: bool = True, max_methods: int | None = 100_000) -> dict[str, Any]:
    apk_path = apk_path.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    log_dir = output_dir / "tool-logs"
    log_dir.mkdir(exist_ok=True)
    if not apk_path.is_file():
        raise FileNotFoundError(f"APK not found: {apk_path}")
    print(f"[apkintel] Hashing input APK ({apk_path.stat().st_size:,} bytes).", file=sys.stderr, flush=True)
    hashes = file_hashes(apk_path)
    print("[apkintel] Opening APK archive for chunked scan.", file=sys.stderr, flush=True)
    sample_sha256 = hashes["sha256"]
    run_started = datetime.now(timezone.utc).isoformat()
    findings: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    dex_rows: list[dict[str, Any]] = []
    string_rows: list[dict[str, Any]] = []
    pattern_hits: dict[str, list[dict[str, Any]]] = {rule_id: [] for rule_id, _, _ in SUSPICIOUS_PATTERNS}
    skipped_or_truncated: list[dict[str, Any]] = []
    strings_truncated = False
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
            last_progress = time.monotonic()
            print(f"[apkintel] Scanning {len(infos):,} archive entries ({expanded:,} expanded bytes).", file=sys.stderr, flush=True)
            for entry_index, info in enumerate(infos, start=1):
                name = info.filename
                if entry_index == 1 or entry_index % 100 == 0 or time.monotonic() - last_progress >= 5:
                    print(f"[apkintel] Archive entry {entry_index:,}/{len(infos):,}: {name}", file=sys.stderr, flush=True)
                    last_progress = time.monotonic()
                if name.startswith("/") or ".." in Path(name).parts:
                    skipped_or_truncated.append({"file": name, "reason": "unsafe_archive_path_not_scanned"})
                    findings.append({"id": "unsafe_archive_path", "severity": "info", "category": "archive", "claim_type": "observed_fact", "message": "Archive contains a path that looks unsafe when extracted; it was not extracted or scanned.", "evidence": [{"file": name}], "confidence": "high"})
                    continue
                row = {"path": name, "compressed_bytes": info.compress_size, "uncompressed_bytes": info.file_size, "compression": info.compress_type, "crc32": f"{info.CRC:08x}", "directory": info.is_dir()}
                if not info.is_dir():
                    try:
                        scan_strings = name.endswith(TEXT_EXTENSIONS) or name.endswith(".dex") or name.endswith(".so")
                        remaining_strings = max(0, MAX_STRING_ROWS - len(string_rows))
                        scanned = _scan_entry(archive, info, scan_strings, max_strings=remaining_strings)
                        row["sha256"] = scanned["sha256"]
                        row["bytes_read"] = scanned["bytes_read"]
                        if scanned["bytes_read"] != info.file_size:
                            skipped_or_truncated.append({"file": name, "reason": "entry_read_incomplete", "expected_bytes": info.file_size, "read_bytes": scanned["bytes_read"]})
                        for rule_id, rows in scanned["pattern_hits"].items():
                            seen = {item["offset_text_chars_approx"] for item in pattern_hits[rule_id] if item["file"] == name}
                            pattern_hits[rule_id].extend(item for item in rows if item["offset_text_chars_approx"] not in seen and len(pattern_hits[rule_id]) < 100)
                        if scan_strings:
                            string_rows.extend(scanned["strings"])
                            if scanned["strings_truncated"] or len(string_rows) >= MAX_STRING_ROWS:
                                if not strings_truncated:
                                    skipped_or_truncated.append({"file": name, "reason": "printable_string_output_limit", "limit": MAX_STRING_ROWS})
                                strings_truncated = True
                        prefix = scanned["prefix"]
                        if name.endswith(".dex") and (name == "classes.dex" or re.fullmatch(r"classes\d+\.dex", name)):
                            dex_rows.append({"path": name, "sha256": row["sha256"], "bytes": scanned["bytes_read"], "magic": prefix[:8].decode("ascii", errors="replace"), "header_checksum_adler32": prefix[8:12].hex() if len(prefix) >= 12 else None, "header_signature_sha1": prefix[12:32].hex() if len(prefix) >= 32 else None, "file_size_header": int.from_bytes(prefix[32:36], "little") if len(prefix) >= 36 else None, "header_size": int.from_bytes(prefix[36:40], "little") if len(prefix) >= 40 else None, "endian_tag": prefix[40:44].hex() if len(prefix) >= 44 else None, "string_ids_size": int.from_bytes(prefix[56:60], "little") if len(prefix) >= 60 else None, "type_ids_size": int.from_bytes(prefix[64:68], "little") if len(prefix) >= 68 else None, "proto_ids_size": int.from_bytes(prefix[72:76], "little") if len(prefix) >= 76 else None, "field_ids_size": int.from_bytes(prefix[80:84], "little") if len(prefix) >= 84 else None, "method_ids_size": int.from_bytes(prefix[88:92], "little") if len(prefix) >= 92 else None, "class_defs_size": int.from_bytes(prefix[96:100], "little") if len(prefix) >= 100 else None, "data_size": int.from_bytes(prefix[104:108], "little") if len(prefix) >= 108 else None, "source": "raw_dex_header", "evidence": {"file": name, "byte_ranges": {"magic": "0x00-0x07", "checksum": "0x08-0x0b", "signature": "0x0c-0x1f", "file_size": "0x20-0x23"}}})
                        if name.endswith(".so") and "/" in name:
                            archive_summary["native_libraries"].append({"path": name, "sha256": row["sha256"], "bytes": scanned["bytes_read"], "elf_magic": prefix[:4] == b"\x7fELF"})
                        if name.startswith(("res/", "assets/")):
                            archive_summary["resource_count"] += 1
                    except Exception as exc:
                        row["read_error"] = f"{type(exc).__name__}: {exc}"
                        skipped_or_truncated.append({"file": name, "reason": "entry_scan_error", "error": row["read_error"]})
                files.append(row)
    except zipfile.BadZipFile as exc:
        raise ValueError("Input is not a readable APK/ZIP archive.") from exc

    archive_summary["dex_count"] = len(dex_rows)
    unique_strings: dict[tuple[str, str], dict[str, Any]] = {}
    for row in string_rows:
        unique_strings.setdefault((row["source_file"], row["value"]), row)
    string_rows = list(unique_strings.values())

    manifest_entry = next((item for item in files if item["path"] == "AndroidManifest.xml"), None)
    if manifest_entry:
        findings.append({"id": "manifest_present", "severity": "info", "category": "manifest", "claim_type": "observed_fact", "message": "AndroidManifest.xml is present in the APK archive.", "evidence": [{"file": "AndroidManifest.xml", "sha256": manifest_entry.get("sha256")}], "confidence": "high"})
    if not dex_rows:
        findings.append({"id": "no_standard_dex_found", "severity": "warning", "category": "coverage", "claim_type": "observed_fact", "message": "No standard classes.dex/classesN.dex entry was found; the APK may be native-only, unusual, packed, or malformed.", "evidence": [{"file": apk_path.name}], "confidence": "medium"})
    if archive_summary["native_libraries"]:
        findings.append({"id": "native_libraries_present", "severity": "info", "category": "native", "claim_type": "observed_fact", "message": "Native shared libraries are included; this initial analyzer fingerprints them but does not fully disassemble them.", "evidence": archive_summary["native_libraries"], "confidence": "high"})
    for rule_id, _, message in SUSPICIOUS_PATTERNS:
        matches = []
        for name in {item["file"] for item in pattern_hits[rule_id]}:
            matches.extend(item for item in pattern_hits[rule_id] if item["file"] == name)
        if matches:
            findings.append({"id": rule_id, "severity": "info", "category": "behavioral_indicator", "claim_type": "heuristic_indicator", "message": message, "evidence": matches[:100], "confidence": "low", "limitations": "String/pattern presence alone does not establish that the code path is reachable or used."})
    if skipped_or_truncated:
        findings.append({"id": "analysis_coverage_limited", "severity": "warning", "category": "coverage", "claim_type": "observed_fact", "message": "One or more archive entries or output streams were skipped, incomplete, or truncated; see manifest coverage notes.", "evidence": skipped_or_truncated[:100], "confidence": "high"})

    if run_androguard:
        androguard_status = _androguard_extract(apk_path, output_dir, max_methods=max_methods)
    else:
        androguard_status = {"available": False, "status": "disabled", "note": "Androguard extraction disabled by --no-androguard.", "max_methods": max_methods, "truncated": False}
        for filename in ("classes.jsonl", "methods.jsonl", "instructions.jsonl", "references.jsonl"):
            (output_dir / filename).write_text("", encoding="utf-8")
    dex_coverage = _dex_coverage_summary(dex_rows, androguard_status, output_dir / "classes.jsonl")
    coverage_warnings = []
    if dex_coverage["dex_count_matches_archive"] is False:
        coverage_warnings.append({
            "kind": "dex_count_mismatch",
            "archive_dex_count": dex_coverage["archive_dex_count"],
            "androguard_dex_count": dex_coverage["androguard_dex_count"],
        })
    for dex_item in dex_coverage["per_dex"]:
        if dex_item["class_count_matches_header"] is False:
            coverage_warnings.append({"kind": "class_count_mismatch", **dex_item})
    if androguard_status.get("truncated"):
        coverage_warnings.append({
            "kind": "method_instruction_output_truncated",
            "max_methods": max_methods,
            "classes_complete": True,
            "methods_emitted": androguard_status.get("methods", 0),
            "note": androguard_status.get("note"),
        })
    if coverage_warnings:
        findings.append({
            "id": "dex_inventory_coverage_mismatch",
            "severity": "warning",
            "category": "coverage",
            "claim_type": "observed_fact",
            "message": "DEX header counts and/or parser output indicate incomplete or capped structured coverage; inspect manifest.json coverage details.",
            "evidence": coverage_warnings[:100],
            "confidence": "high",
        })
    _attach_method_level_evidence(findings, output_dir / "instructions.jsonl")

    tools: list[dict[str, Any]] = []
    if run_optional_tools:
        tools.append(_run_tool("jadx", ["jadx", "-d", str(output_dir / "jadx"), str(apk_path)], log_dir, timeout=900, java_opts="-Xmx3g"))
        tools.append(_run_tool("apktool", ["apktool", "d", "-f", str(apk_path), "-o", str(output_dir / "apktool")], log_dir, timeout=600, java_opts="-Xmx2g"))
        tools.append(_run_tool("apkid", ["apkid", str(apk_path)], log_dir, timeout=180))

    versions = {"apkintel": __version__, "python": sys.version.split()[0], "androguard": None}
    try:
        versions["androguard"] = importlib.metadata.version("androguard")
    except importlib.metadata.PackageNotFoundError:
        pass
    tool_inventory = {"jadx": tool_version("jadx"), "apktool": tool_version("apktool"), "apkid": tool_version("apkid"), "androguard": {"available": androguard_status.get("available", False), "status": androguard_status.get("status")}}
    manifest = {"schema_version": "1.0", "tool": "APK Intelligence", "tool_version": __version__, "analysis_started_utc": run_started, "analysis_finished_utc": datetime.now(timezone.utc).isoformat(), "sample": {"filename": apk_path.name, "size_bytes": apk_path.stat().st_size, "sha256": sample_sha256, "sha1": hashes["sha1"], "md5": hashes["md5"]}, "archive": archive_summary, "tool_versions": versions, "tool_inventory": tool_inventory, "androguard_extraction": androguard_status, "app_metadata": androguard_status.get("app_metadata"), "optional_tools": tools, "coverage": {"static_only": True, "apk_executed": False, "decompilation_is_lossless": False, "native_analysis": "fingerprints only in initial version", "string_offsets": "approximate byte offsets of printable ASCII sequences", "androguard_enabled": run_androguard, "max_methods": max_methods, "androguard_truncated": bool(androguard_status.get("truncated")), "dex_inventory": dex_coverage, "coverage_warnings": coverage_warnings, "strings_truncated": strings_truncated, "skipped_or_truncated_files": skipped_or_truncated, "notes": ["APK files are never executed.", "Archive members are hashed and scanned in chunks; printable strings are extracted only from text-like files, DEX, and native libraries.", "Packed/encrypted payloads and runtime-loaded code may not be visible.", "Pattern matches are indicators, not proof of malicious behavior.", "DEX raw-header hashes are exact; class/method inventory depends on optional parser support."] + (["Printable-string output was capped at MAX_STRING_ROWS."] if strings_truncated else []) + ([androguard_status["note"]] if androguard_status.get("truncated") and androguard_status.get("note") else [])}}

    _jsonl(output_dir / "files.jsonl", files)
    _jsonl(output_dir / "dex.jsonl", dex_rows)
    _jsonl(output_dir / "strings.jsonl", string_rows)
    (output_dir / "findings.json").write_text(json.dumps({"schema_version": "1.0", "findings": findings}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    counts = Counter(row["category"] for row in findings)
    summary = ["# APK Intelligence Report", "", f"- **Sample:** {apk_path.name}", f"- **SHA-256:** {sample_sha256}", f"- **Size:** {apk_path.stat().st_size:,} bytes", f"- **DEX files:** {len(dex_rows)}", f"- **Archive entries:** {len(files)}", f"- **Extracted printable strings:** {len(string_rows)}", f"- **Parsed classes / methods:** {androguard_status.get('classes', 0)} / {androguard_status.get('methods', 0)}", f"- **Instructions / cross-references:** {androguard_status.get('instructions', 0)} / {androguard_status.get('references', 0)}", f"- **Static findings:** {len(findings)}", "", "## Finding categories", ""]
    summary.extend([f"- {key}: {value}" for key, value in sorted(counts.items())] or ["- None"])
    summary.extend(["", "## DEX fingerprints", ""])
    summary.extend([f"- {row['path']} — SHA-256 {row['sha256']}, {row['bytes']:,} bytes, magic {row['magic']}" for row in dex_rows] or ["- No standard DEX entries detected."])
    summary.extend(["", "## Evidence and interpretation", "", "Findings distinguish observed facts from heuristic indicators. Pattern matches are not proof of maliciousness, and static analysis cannot reveal all runtime behavior. See findings.json, manifest.json, and JSONL indexes for machine-readable data.", "", "## Optional tool results", ""])
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
    analyze.add_argument("--no-androguard", action="store_true", help="Skip Androguard parsing.")
    analyze.add_argument("--max-methods", type=int, default=100_000, help="Maximum methods to emit from Androguard (0 means unlimited).")
    analyze.add_argument("--require-androguard", action="store_true", help="Return a nonzero exit code unless Androguard extraction succeeds.")
    fetch = sub.add_parser("analyze-url", help="Safely download an HTTPS APK URL and analyze it.")
    fetch.add_argument("url")
    fetch.add_argument("--out", type=Path, default=Path("analysis-output"))
    fetch.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    fetch.add_argument("--no-optional-tools", action="store_true")
    fetch.add_argument("--no-androguard", action="store_true")
    fetch.add_argument("--max-methods", type=int, default=100_000)
    fetch.add_argument("--require-androguard", action="store_true", help="Return a nonzero exit code unless Androguard extraction succeeds.")
    args = parser.parse_args(argv)
    try:
        if args.max_methods < 0:
            raise ValueError("--max-methods must be zero (unlimited) or a positive integer")
        max_methods = None if args.max_methods == 0 else args.max_methods
        if args.command == "analyze-url":
            sample_dir = args.out / "input"
            sample_dir.mkdir(parents=True, exist_ok=True)
            apk_path = download_apk(args.url, sample_dir / "sample.apk", args.max_bytes)
        else:
            apk_path = args.apk
        manifest = analyze_apk(apk_path, args.out, run_optional_tools=not args.no_optional_tools, run_androguard=not args.no_androguard, max_methods=max_methods)
        print(json.dumps({"status": "ok", "output_dir": str(args.out.resolve()), "sha256": manifest["sample"]["sha256"], "dex_count": manifest["archive"]["dex_count"], "report": str((args.out / "summary.md").resolve())}, indent=2))
        if args.require_androguard and manifest.get("androguard_extraction", {}).get("status") != "ok":
            print("apkintel: Androguard was required but extraction did not succeed; see manifest.json.", file=sys.stderr)
            return 3
        return 0
    except Exception as exc:
        print(f"apkintel: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
