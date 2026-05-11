"""
Digest algorithms with SM3 support.
"""

import hashlib
from enum import Enum


class DigestAlgorithm(Enum):
    """Supported digest algorithms."""
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    SM3 = "sm3"


# OID mappings for digest algorithms
DIGEST_OID_MAP = {
    DigestAlgorithm.SHA256: "2.16.840.1.101.3.4.2.1",
    DigestAlgorithm.SHA384: "2.16.840.1.101.3.4.2.2",
    DigestAlgorithm.SHA512: "2.16.840.1.101.3.4.2.3",
    DigestAlgorithm.SM3: "1.2.156.10197.1.401",
}

# Reverse map: OID string -> DigestAlgorithm
OID_TO_ALGORITHM = {v: k for k, v in DIGEST_OID_MAP.items()}


def compute_hash(data: bytes, algorithm: DigestAlgorithm = DigestAlgorithm.SHA256) -> bytes:
    """
    Compute hash of the given data.

    Args:
        data: The data to hash.
        algorithm: The hash algorithm to use.

    Returns:
        The hash digest as bytes.
    """
    if algorithm == DigestAlgorithm.SM3:
        return _sm3_hash(data)
    return hashlib.new(algorithm.value, data).digest()


def compute_hash_for_file(filepath: str, algorithm: DigestAlgorithm = DigestAlgorithm.SHA256) -> bytes:
    """
    Compute hash of a file.

    Args:
        filepath: Path to the file.
        algorithm: The hash algorithm to use.

    Returns:
        The hash digest as bytes.
    """
    if algorithm == DigestAlgorithm.SM3:
        with open(filepath, "rb") as f:
            return _sm3_hash(f.read())

    h = hashlib.new(algorithm.value)
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.digest()


def _sm3_hash(data: bytes) -> bytes:
    """
    Compute SM3 hash using gmssl or OpenSSL fallback.
    SM3 is defined in GB/T 32905-2016.
    """
    try:
        from gmssl import sm3 as _sm3
        return bytes.fromhex(_sm3.sm3_hash(list(data)))
    except ImportError:
        pass

    # Fallback: use openssl command line
    import subprocess
    try:
        result = subprocess.run(
            ["openssl", "dgst", "-sm3", "-binary"],
            input=data,
            capture_output=True,
            check=True,
        )
        return result.stdout
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        raise RuntimeError(
            "SM3 requires 'gmssl' Python package or OpenSSL 1.1.1+. "
            "Install with: pip install gmssl"
        ) from e
