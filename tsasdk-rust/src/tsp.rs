//! RFC 3161 TSA client implementation.

use crate::digest::{compute_hash_for_data, DigestAlgorithm};
use base64::Engine;
use thiserror::Error;

/// TSA client errors.
#[derive(Error, Debug)]
pub enum TsaError {
    #[error("HTTP request failed: {0}")]
    HttpError(String),

    #[error("TSA returned HTTP {0}")]
    HttpErrorStatus(u16),

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("ASN.1 encoding error: {0}")]
    Asn1Error(String),
}

/// RFC 3161 TSA Client.
///
/// Supports SHA-256, SHA-384, SHA-512, and SM3 digest algorithms.
pub struct TSAClient {
    tsa_url: String,
    username: String,
    password: String,
    timeout: std::time::Duration,
    default_algorithm: DigestAlgorithm,
}

impl TSAClient {
    /// Create a new TSA client.
    pub fn new(tsa_url: &str) -> Self {
        Self::builder(tsa_url).build()
    }

    /// Create a builder for configuring the TSA client.
    pub fn builder(tsa_url: &str) -> TSAClientBuilder {
        TSAClientBuilder {
            tsa_url: tsa_url.to_string(),
            username: String::new(),
            password: String::new(),
            timeout: std::time::Duration::from_secs(10),
            default_algorithm: DigestAlgorithm::SHA256,
        }
    }

    /// Request a timestamp token for the given data.
    pub fn timestamp_data(
        &self,
        data: &[u8],
        algorithm: Option<DigestAlgorithm>,
    ) -> Result<Vec<u8>, TsaError> {
        let algo = algorithm.unwrap_or(self.default_algorithm);
        let hash_bytes = compute_hash_for_data(data, algo);
        self.timestamp_hash(&hash_bytes, Some(algo))
    }

    /// Request a timestamp token for a pre-computed hash.
    pub fn timestamp_hash(
        &self,
        hash_bytes: &[u8],
        algorithm: Option<DigestAlgorithm>,
    ) -> Result<Vec<u8>, TsaError> {
        let algo = algorithm.unwrap_or(self.default_algorithm);
        let request_bytes = self.build_timestamp_request(hash_bytes, algo)?;
        self.send_request(&request_bytes)
    }

    fn build_timestamp_request(
        &self,
        hash_bytes: &[u8],
        algorithm: DigestAlgorithm,
    ) -> Result<Vec<u8>, TsaError> {
        let oid_str = algorithm.oid();
        let mut encoder = Asn1Encoder::new();

        // TimeStampReq ::= SEQUENCE { version, messageImprint, nonce, certReq }
        let request = encoder.encode_sequence(|seq| {
            // version = 1
            seq.encode_integer(1);

            // MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }
            seq.encode_sequence(|mi| {
                // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL }
                mi.encode_sequence(|ai| {
                    ai.encode_oid(oid_str);
                    ai.encode_null();
                });
                mi.encode_octet_string(hash_bytes);
            });

            // nonce
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            seq.encode_integer(nonce);

            // certReq = true
            seq.encode_boolean(true);
        });

        Ok(request)
    }

    fn send_request(&self, request_bytes: &[u8]) -> Result<Vec<u8>, TsaError> {
        let mut request = ureq::post(&self.tsa_url)
            .set("Content-Type", "application/timestamp-query")
            .set("Content-Transfer-Encoding", "binary")
            .timeout(self.timeout);

        if !self.username.is_empty() {
            let engine = base64::engine::general_purpose::STANDARD;
            let auth = engine.encode(format!("{}:{}", self.username, self.password));
            request = request.set("Authorization", &format!("Basic {}", auth));
        }

        let response = request
            .send_bytes(request_bytes)
            .map_err(|e| TsaError::HttpError(e.to_string()))?;

        let status = response.status();
        if status != 200 {
            return Err(TsaError::HttpErrorStatus(status));
        }

        let content_transfer = response
            .header("Content-Transfer-Encoding")
            .map(|s| s.to_string());

        let mut body = Vec::new();
        response
            .into_reader()
            .read_to_end(&mut body)
            .map_err(|e| TsaError::HttpError(e.to_string()))?;

        if content_transfer.as_deref() == Some("base64") {
            let engine = base64::engine::general_purpose::STANDARD;
            return Ok(engine.decode(&body)?);
        }

        Ok(body)
    }
}

/// Builder for TSAClient.
pub struct TSAClientBuilder {
    tsa_url: String,
    username: String,
    password: String,
    timeout: std::time::Duration,
    default_algorithm: DigestAlgorithm,
}

impl TSAClientBuilder {
    pub fn username(mut self, username: &str) -> Self {
        self.username = username.to_string();
        self
    }

    pub fn password(mut self, password: &str) -> Self {
        self.password = password.to_string();
        self
    }

    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn default_algorithm(mut self, algorithm: DigestAlgorithm) -> Self {
        self.default_algorithm = algorithm;
        self
    }

    pub fn build(self) -> TSAClient {
        TSAClient {
            tsa_url: self.tsa_url,
            username: self.username,
            password: self.password,
            timeout: self.timeout,
            default_algorithm: self.default_algorithm,
        }
    }
}

// --- Minimal ASN.1 DER encoder ---

struct Asn1Encoder {
    output: Vec<u8>,
}

impl Asn1Encoder {
    fn new() -> Self {
        Self { output: Vec::new() }
    }

    fn encode_sequence<F>(&mut self, f: F) -> Vec<u8>
    where
        F: FnOnce(&mut Asn1Encoder),
    {
        let mut inner = Asn1Encoder::new();
        f(&mut inner);
        let content = inner.output;
        let mut result = Vec::new();
        result.push(0x30);
        Self::append_length(&mut result, content.len());
        result.extend_from_slice(&content);
        self.output.extend_from_slice(&result);
        result
    }

    fn encode_oid(&mut self, oid_str: &str) {
        let components: Vec<u64> = oid_str.split('.').map(|s| s.parse().unwrap()).collect();
        let mut oid_bytes = Vec::new();
        oid_bytes.push((components[0] * 40 + components[1]) as u8);

        for &comp in &components[2..] {
            if comp == 0 {
                oid_bytes.push(0);
            } else {
                let mut sub = Vec::new();
                let mut val = comp;
                sub.push((val & 0x7F) as u8);
                val >>= 7;
                while val > 0 {
                    sub.insert(0, (0x80 | (val & 0x7F)) as u8);
                    val >>= 7;
                }
                oid_bytes.extend(sub);
            }
        }

        let mut result = Vec::new();
        result.push(0x06);
        Self::append_length(&mut result, oid_bytes.len());
        result.extend_from_slice(&oid_bytes);
        self.output.extend_from_slice(&result);
    }

    fn encode_null(&mut self) {
        self.output.extend_from_slice(&[0x05, 0x00]);
    }

    fn encode_octet_string(&mut self, data: &[u8]) {
        let mut result = Vec::new();
        result.push(0x04);
        Self::append_length(&mut result, data.len());
        result.extend_from_slice(data);
        self.output.extend_from_slice(&result);
    }

    fn encode_integer(&mut self, value: i64) {
        let mut content = Vec::new();
        if value == 0 {
            content.push(0);
        } else {
            let mut n = if value < 0 {
                -(value as i64)
            } else {
                value as i64
            };
            let mut bytes = Vec::new();
            while n > 0 {
                bytes.insert(0, (n & 0xFF) as u8);
                n >>= 8;
            }
            if bytes[0] & 0x80 != 0 {
                bytes.insert(0, 0);
            }
            content = bytes;
        }
        let mut result = Vec::new();
        result.push(0x02);
        Self::append_length(&mut result, content.len());
        result.extend_from_slice(&content);
        self.output.extend_from_slice(&result);
    }

    fn encode_boolean(&mut self, value: bool) {
        self.output
            .extend_from_slice(&[0x01, 0x01, if value { 0xFF } else { 0x00 }]);
    }

    fn append_length(buf: &mut Vec<u8>, length: usize) {
        if length < 0x80 {
            buf.push(length as u8);
        } else {
            let mut bytes = Vec::new();
            let mut n = length;
            while n > 0 {
                bytes.insert(0, (n & 0xFF) as u8);
                n >>= 8;
            }
            buf.push(0x80 | bytes.len() as u8);
            buf.extend(bytes);
        }
    }
}
