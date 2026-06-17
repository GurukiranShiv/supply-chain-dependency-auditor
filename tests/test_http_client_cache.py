import os
import tempfile
import unittest
from pathlib import Path

from auditor.http_client import _cache_path, _read_cache, _write_cache, sha256_bytes, sha512_base64


class HttpClientCacheTests(unittest.TestCase):
    def test_cache_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            old = os.environ.get("AUDITOR_CACHE_DIR")
            os.environ["AUDITOR_CACHE_DIR"] = td
            try:
                _write_cache("https://example.test/data", b"hello")
                self.assertEqual(_read_cache("https://example.test/data"), b"hello")
                self.assertTrue(_cache_path("https://example.test/data").exists())
            finally:
                if old is None:
                    os.environ.pop("AUDITOR_CACHE_DIR", None)
                else:
                    os.environ["AUDITOR_CACHE_DIR"] = old

    def test_hash_helpers(self):
        self.assertEqual(sha256_bytes(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertTrue(sha512_base64(b"abc"))


if __name__ == "__main__":
    unittest.main()
