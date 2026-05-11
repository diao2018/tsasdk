import unittest

from tsasdk.crypto.digest import DIGEST_OID_MAP, DigestAlgorithm, compute_hash


class DigestTest(unittest.TestCase):
    def test_sha256_known_vector(self):
        self.assertEqual(
            compute_hash(b"abc", DigestAlgorithm.SHA256).hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_sm3_known_vector(self):
        self.assertEqual(
            compute_hash(b"abc", DigestAlgorithm.SM3).hex(),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        )

    def test_sm3_oid(self):
        self.assertEqual(DIGEST_OID_MAP[DigestAlgorithm.SM3], "1.2.156.10197.1.401")


if __name__ == "__main__":
    unittest.main()
