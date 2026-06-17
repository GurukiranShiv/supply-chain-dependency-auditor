import tempfile
import unittest
from pathlib import Path

from auditor.diff_scan import diff_packages, save_baseline


class DiffTests(unittest.TestCase):
    def test_diff_added_and_changed(self):
        old = [{"name": "a", "ecosystem": "pip", "version": "1.0"}]
        new = [
            {"name": "a", "ecosystem": "pip", "version": "2.0"},
            {"name": "b", "ecosystem": "pip", "version": "1.0"},
        ]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "baseline.json"
            save_baseline(old, str(path))
            diff = diff_packages(new, str(path))
        self.assertEqual(len(diff["changed"]), 1)
        self.assertEqual(len(diff["added"]), 1)


if __name__ == "__main__":
    unittest.main()
