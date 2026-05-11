//! Digest algorithms and hash computation.

use sha2::{Digest, Sha256, Sha384, Sha512};
use sm3::Sm3;

/// Supported digest algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    SHA256,
    SHA384,
    SHA512,
    SM3,
}

/// OID strings for digest algorithms.
impl DigestAlgorithm {
    pub fn oid(&self) -> &'static str {
        match self {
            DigestAlgorithm::SHA256 => "2.16.840.1.101.3.4.2.1",
            DigestAlgorithm::SHA384 => "2.16.840.1.101.3.4.2.2",
            DigestAlgorithm::SHA512 => "2.16.840.1.101.3.4.2.3",
            DigestAlgorithm::SM3 => "1.2.156.10197.1.401",
        }
    }

    /// Hash output size in bytes.
    pub fn hash_size(&self) -> usize {
        match self {
            DigestAlgorithm::SHA256 => 32,
            DigestAlgorithm::SHA384 => 48,
            DigestAlgorithm::SHA512 => 64,
            DigestAlgorithm::SM3 => 32,
        }
    }
}

/// Compute hash of the given data.
pub fn compute_hash_for_data(data: &[u8], algorithm: DigestAlgorithm) -> Vec<u8> {
    match algorithm {
        DigestAlgorithm::SHA256 => Sha256::digest(data).to_vec(),
        DigestAlgorithm::SHA384 => Sha384::digest(data).to_vec(),
        DigestAlgorithm::SHA512 => Sha512::digest(data).to_vec(),
        DigestAlgorithm::SM3 => Sm3::digest(data).to_vec(),
    }
}

/// Convenience: compute hash of a UTF-8 string.
pub fn compute_hash(text: &str, algorithm: DigestAlgorithm) -> Vec<u8> {
    compute_hash_for_data(text.as_bytes(), algorithm)
}

#[cfg(test)]
mod tests {
    use super::{compute_hash, DigestAlgorithm};

    #[test]
    fn computes_sha256_known_vector() {
        assert_eq!(
            hex::encode(compute_hash("abc", DigestAlgorithm::SHA256)),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn computes_sm3_known_vector() {
        assert_eq!(
            hex::encode(compute_hash("abc", DigestAlgorithm::SM3)),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );
    }

    #[test]
    fn exposes_sm3_oid() {
        assert_eq!(DigestAlgorithm::SM3.oid(), "1.2.156.10197.1.401");
    }
}
