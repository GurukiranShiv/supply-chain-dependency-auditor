import unittest
from unittest.mock import patch

from auditor.typosquat import check_typosquat, levenshtein_distance, similarity_ratio


class TyposquatEdgeTests(unittest.TestCase):
    def test_exact_popular_package_is_not_suspicious(self):
        result = check_typosquat("requests", "pip")
        self.assertFalse(result["is_suspicious"])
        self.assertEqual(result["distance"], 0)
        self.assertEqual(result["similarity"], 1.0)

    def test_single_character_typo_is_suspicious(self):
        result = check_typosquat("reques7s", "pip")
        self.assertTrue(result["is_suspicious"])
        self.assertEqual(result["closest_match"], "requests")
        self.assertLessEqual(result["distance"], 2)

    def test_normalized_number_substitution_is_suspicious(self):
        with patch("auditor.typosquat.load_popular_packages", return_value=["lodash"]):
            result = check_typosquat("l0dash", "npm")
        self.assertTrue(result["is_suspicious"])
        self.assertEqual(result["closest_match"], "lodash")

    def test_distance_and_ratio_helpers(self):
        self.assertEqual(levenshtein_distance("flask", "flask"), 0)
        self.assertEqual(levenshtein_distance("flsak", "flask"), 2)
        self.assertGreater(similarity_ratio("requests", "reques7s"), 0.85)


if __name__ == "__main__":
    unittest.main()
