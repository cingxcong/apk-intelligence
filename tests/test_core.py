import json
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from pathlib import Path

from apkintel.cli import analyze_apk
from apkintel import downloader
from apkintel.downloader import _validate_url


class AnalyzerTests(unittest.TestCase):
    def test_analyze_synthetic_apk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / 'sample.apk'
            # Minimal ZIP-shaped fixture; the DEX header is intentionally synthetic.
            dex = bytearray(112)
            dex[:8] = b'dex\n035\x00'
            dex[32:36] = (112).to_bytes(4, 'little')
            dex[36:40] = (0x70).to_bytes(4, 'little')
            with zipfile.ZipFile(apk, 'w') as z:
                z.writestr('AndroidManifest.xml', b'fake manifest fixture')
                z.writestr('classes.dex', bytes(dex))
                z.writestr('assets/config.txt', 'https://example.invalid/api\n')
            out = root / 'out'
            manifest = analyze_apk(apk, out, run_optional_tools=False)
            self.assertEqual(manifest['sample']['sha256'], __import__('hashlib').sha256(apk.read_bytes()).hexdigest())
            self.assertEqual(manifest['archive']['dex_count'], 1)
            self.assertTrue((out / 'files.jsonl').is_file())
            self.assertTrue((out / 'findings.json').is_file())
            dex_rows = [json.loads(x) for x in (out / 'dex.jsonl').read_text().splitlines()]
            self.assertEqual(dex_rows[0]['path'], 'classes.dex')

    def test_url_requires_https(self):
        with self.assertRaises(ValueError):
            _validate_url('http://example.com/app.apk')

    def test_url_rejects_localhost(self):
        with self.assertRaises(ValueError):
            _validate_url('https://localhost/app.apk')

    def test_incomplete_download_is_rejected_and_partial_file_removed(self):
        class FakeResponse:
            headers = {"Content-Length": "100"}
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def geturl(self):
                return "https://example.com/sample.apk"
            def read(self, size=-1):
                if not hasattr(self, "sent"):
                    self.sent = True
                    return b"PK\\x03\\x04" + b"x" * 12
                return b""

        class FakeOpener:
            def open(self, request, timeout=30):
                return FakeResponse()

        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "sample.apk"
            with patch.object(downloader, "_validate_url", return_value="https://example.com/sample.apk"), \\
                 patch.object(downloader.urllib.request, "build_opener", return_value=FakeOpener()):
                with self.assertRaisesRegex(ValueError, "Incomplete download"):
                    downloader.download_apk("https://example.com/sample.apk", destination)
            self.assertFalse(destination.exists())
            self.assertFalse(destination.with_suffix(".apk.part").exists())


if __name__ == '__main__':
    unittest.main()
