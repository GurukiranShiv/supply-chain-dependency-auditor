import unittest
from unittest.mock import patch

from auditor.provenance import check_provenance


class ProvenanceTests(unittest.TestCase):
    def test_npm_integrity_verified(self):
        registry = {"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {"dist": {"integrity": "sha512-abc", "tarball": "https://registry.npmjs.org/a.tgz", "signatures": [{"sig": "x"}]}}}}
        scan = {"artifact_sha512_base64": "abc", "artifact_url": "https://registry.npmjs.org/a.tgz"}
        with patch("auditor.provenance.fetch_json", return_value=registry):
            result = check_provenance("demo", "npm", "1.0.0", scan)
        self.assertTrue(result["artifact_integrity_verified"])
        self.assertTrue(result["provenance_attestation_present"])

    def test_npm_integrity_mismatch(self):
        registry = {"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {"dist": {"integrity": "sha512-abc"}}}}
        with patch("auditor.provenance.fetch_json", return_value=registry):
            result = check_provenance("demo", "npm", "1.0.0", {"artifact_sha512_base64": "wrong"})
        self.assertFalse(result["artifact_integrity_verified"])
        self.assertTrue(any("does not match" in f for f in result["flags"]))

    def test_pypi_sha256_verified(self):
        registry = {"info": {"version": "1.0.0"}, "urls": [{"url": "https://files.pythonhosted.org/demo.tar.gz", "digests": {"sha256": "abc"}}]}
        scan = {"artifact_url": "https://files.pythonhosted.org/demo.tar.gz", "artifact_sha256": "abc"}
        with patch("auditor.provenance.fetch_json", return_value=registry):
            result = check_provenance("demo", "pip", "1.0.0", scan)
        self.assertTrue(result["artifact_integrity_verified"])
        self.assertTrue(result["registry_digest_present"])


if __name__ == "__main__":
    unittest.main()
