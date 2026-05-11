"""
Demo script for tsasdk-python
"""
from tsasdk import TSAClient, DigestAlgorithm, compute_hash

# SHA-256 demo
print("--- SHA-256 Demo ---")
client = TSAClient(
    tsa_url="http://test1.tsa.cn/tsa",
    username="tsademo",
    password="tsademo",
    digest_algorithm=DigestAlgorithm.SHA256,
)

hash_bytes = compute_hash(b"hello tsa", DigestAlgorithm.SHA256)
print(f"SHA-256 hash: {hash_bytes.hex()}")

try:
    token = client.timestamp_hash(hash_bytes, DigestAlgorithm.SHA256)
    print(f"Token length: {len(token)}")
except Exception as e:
    print(f"Error: {e}")

# SM3 demo
print("\n--- SM3 Demo ---")
sm3_client = TSAClient(
    tsa_url="http://test1.tsa.cn/tsa",
    username="tsademo",
    password="tsademo",
    digest_algorithm=DigestAlgorithm.SM3,
)

sm3_hash = compute_hash(b"hello tsa sm3", DigestAlgorithm.SM3)
print(f"SM3 hash: {sm3_hash.hex()}")

try:
    token = sm3_client.timestamp_hash(sm3_hash, DigestAlgorithm.SM3)
    print(f"SM3 Token length: {len(token)}")
except Exception as e:
    print(f"Error: {e}")
