"""Guarded HTTPS download helper for untrusted user-supplied APK URLs."""
from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_MAX_BYTES = 250 * 1024 * 1024


def _validate_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Only absolute HTTPS URLs are accepted.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    host = parsed.hostname.rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise ValueError("Local hostnames are not accepted.")
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve download host: {host}") from exc
    if not addresses or any(not (addr.is_global and not addr.is_multicast and not addr.is_unspecified) for addr in addresses):
        raise ValueError("Local, private, reserved, or non-public IP destinations are not accepted.")
    return url


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_apk(url: str, destination: str | Path, max_bytes: int = DEFAULT_MAX_BYTES) -> Path:
    """Download an APK over validated HTTPS with redirect and size checks."""
    _validate_url(url)
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(_SafeRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "APK-Intelligence/0.1", "Accept": "application/vnd.android.package-archive, application/octet-stream;q=0.9, */*;q=0.1"})
    temporary = destination.with_suffix(destination.suffix + ".part")
    total = 0
    try:
        with opener.open(request, timeout=30) as response, temporary.open("wb") as out:
            final_url = response.geturl()
            _validate_url(final_url)
            length = response.headers.get("Content-Length")
            if length and int(length) > max_bytes:
                raise ValueError(f"Download exceeds size limit ({max_bytes} bytes).")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"Download exceeds size limit ({max_bytes} bytes).")
                out.write(chunk)
        if total < 8:
            raise ValueError("Downloaded file is too small to be a valid APK.")
        with temporary.open("rb") as handle:
            if handle.read(4) != b"PK\x03\x04":
                raise ValueError("Downloaded content is not a ZIP/APK archive (ZIP signature missing).")
        temporary.replace(destination)
        return destination
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
