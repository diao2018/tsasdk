//! tsasdk - RFC 3161 compliant TSA client with SM3 support
//!
//! Supports SHA-256, SHA-384, SHA-512, and SM3 digest algorithms.

mod digest;
mod tsp;

pub use digest::{compute_hash, compute_hash_for_data, DigestAlgorithm};
pub use tsp::TSAClient;
