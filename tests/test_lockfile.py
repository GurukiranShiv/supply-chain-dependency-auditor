import tempfile
import unittest
from pathlib import Path

from auditor.lockfile import parse_requirements_txt, parse_package_lock


class LockfileParserTests(unittest.TestCase):
    def test_requirements_detects_unpinned_and_hashes(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "requirements.txt"
            path.write_text(
                "requests==2.32.3 --hash=sha256:" + "a" * 64 + "\nflask>=3\n",
                encoding="utf-8",
            )
            pkgs = parse_requirements_txt(str(path))
        self.assertEqual(pkgs[0]["name"], "requests")
        self.assertEqual(pkgs[0]["version"], "2.32.3")
        self.assertEqual(len(pkgs[0]["hashes"]), 1)
        self.assertEqual(pkgs[1]["version"], "unpinned")

    def test_package_lock_reads_integrity(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "package-lock.json"
            path.write_text(
                '{"packages":{"":{"dependencies":{"lodash":"4.17.21"}},'
                '"node_modules/lodash":{"version":"4.17.21","integrity":"sha512-test"}}}',
                encoding="utf-8",
            )
            pkgs = parse_package_lock(str(path))
        self.assertEqual(pkgs[0]["name"], "lodash")
        self.assertEqual(pkgs[0]["integrity"], "sha512-test")
        self.assertEqual(pkgs[0]["source_type"], "direct")


if __name__ == "__main__":
    unittest.main()
