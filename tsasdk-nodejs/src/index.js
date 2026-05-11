'use strict';

const crypto = require('crypto');
const http = require('http');
const https = require('https');
const url = require('url');

/**
 * Supported digest algorithms.
 */
const DigestAlgorithm = {
  SHA256: 'sha256',
  SHA384: 'sha384',
  SHA512: 'sha512',
  SM3: 'sm3'
};

/**
 * OID mappings for digest algorithms.
 */
const DIGEST_OID = {
  [DigestAlgorithm.SHA256]: '2.16.840.1.101.3.4.2.1',
  [DigestAlgorithm.SHA384]: '2.16.840.1.101.3.4.2.2',
  [DigestAlgorithm.SHA512]: '2.16.840.1.101.3.4.2.3',
  [DigestAlgorithm.SM3]: '1.2.156.10197.1.401'
};

/**
 * Compute hash of the given data.
 * @param {Buffer|string} data - Data to hash.
 * @param {string} algorithm - Digest algorithm.
 * @returns {Buffer} Hash digest.
 */
function computeHash(data, algorithm = DigestAlgorithm.SHA256) {
  if (typeof data === 'string') {
    data = Buffer.from(data, 'utf-8');
  }

  if (algorithm === DigestAlgorithm.SM3) {
    return computeSM3Hash(data);
  }

  return crypto.createHash(algorithm).update(data).digest();
}

/**
 * Compute SM3 hash using sm-crypto or OpenSSL fallback.
 * @param {Buffer} data
 * @returns {Buffer}
 */
function computeSM3Hash(data) {
  try {
    const sm3 = require('sm-crypto').sm3;
    const hex = sm3(Array.from(data));
    return Buffer.from(hex, 'hex');
  } catch (_) {
    // Fallback: use OpenSSL command
    const { execFileSync } = require('child_process');
    try {
      const result = execFileSync('openssl', ['dgst', '-sm3', '-binary'], {
        input: data,
        maxBuffer: 10 * 1024 * 1024
      });
      return result;
    } catch (e) {
      throw new Error(
        "SM3 requires 'sm-crypto' npm package or OpenSSL 1.1.1+. Install with: npm install sm-crypto"
      );
    }
  }
}

// --- ASN.1 DER encoding helpers ---

function encodeLength(length) {
  if (length < 0x80) {
    return Buffer.from([length]);
  }
  const bytes = [];
  let n = length;
  while (n > 0) {
    bytes.unshift(n & 0xFF);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function encodeTLV(tag, content) {
  const len = encodeLength(content.length);
  return Buffer.concat([Buffer.from([tag]), len, content]);
}

function encodeOID(oidString) {
  const components = oidString.split('.').map(Number);
  const encoded = [components[0] * 40 + components[1]];

  for (let i = 2; i < components.length; i++) {
    let val = components[i];
    if (val === 0) {
      encoded.push(0);
    } else {
      const sub = [];
      sub.unshift(val & 0x7F);
      val >>>= 7;
      while (val > 0) {
        sub.unshift(0x80 | (val & 0x7F));
        val >>>= 7;
      }
      encoded.push(...sub);
    }
  }

  return encodeTLV(0x06, Buffer.from(encoded));
}

function encodeNull() {
  return Buffer.from([0x05, 0x00]);
}

function encodeAlgorithmIdentifier(oidString) {
  return encodeTLV(0x30, Buffer.concat([encodeOID(oidString), encodeNull()]));
}

function encodeOctetString(data) {
  return encodeTLV(0x04, data);
}

function encodeInteger(value) {
  if (value === 0) {
    return encodeTLV(0x02, Buffer.from([0]));
  }
  const bytes = [];
  let n = value;
  while (n > 0) {
    bytes.unshift(n & 0xFF);
    n >>>= 8;
  }
  if (bytes[0] & 0x80) {
    bytes.unshift(0);
  }
  return encodeTLV(0x02, Buffer.from(bytes));
}

function encodeBoolean(value) {
  return Buffer.from([0x01, 0x01, value ? 0xFF : 0x00]);
}

function encodeSequence(content) {
  return encodeTLV(0x30, content);
}

/**
 * Build RFC 3161 TimeStampReq DER-encoded bytes.
 */
function buildTimestampRequest(hashBytes, digestOid, certReq = true) {
  // MessageImprint
  const messageImprint = encodeSequence(
    Buffer.concat([encodeAlgorithmIdentifier(digestOid), encodeOctetString(hashBytes)])
  );

  // TimeStampReq
  const nonce = Date.now();
  const content = Buffer.concat([
    encodeInteger(1),          // version
    messageImprint,            // messageImprint
    encodeInteger(nonce),      // nonce
    ...(certReq ? [encodeBoolean(true)] : [])
  ]);

  return encodeSequence(content);
}

/**
 * RFC 3161 TSA Client.
 */
class TSAClient {
  /**
   * @param {string} tsaUrl - URL of the TSA server.
   * @param {object} options - Options.
   * @param {string} [options.username] - Basic Auth username.
   * @param {string} [options.password] - Basic Auth password.
   * @param {number} [options.timeout=10000] - HTTP timeout in ms.
   * @param {string} [options.digestAlgorithm='sha256'] - Default digest algorithm.
   */
  constructor(tsaUrl, options = {}) {
    this.tsaUrl = tsaUrl;
    this.username = options.username || '';
    this.password = options.password || '';
    this.timeout = options.timeout || 10000;
    this.digestAlgorithm = options.digestAlgorithm || DigestAlgorithm.SHA256;
  }

  /**
   * Request a timestamp token for the given data.
   * @param {Buffer|string} data
   * @param {string} [algorithm]
   * @returns {Promise<Buffer>}
   */
  async timestampData(data, algorithm) {
    const algo = algorithm || this.digestAlgorithm;
    const hashBytes = computeHash(data, algo);
    return this.timestampHash(hashBytes, algo);
  }

  /**
   * Request a timestamp token for a pre-computed hash.
   * @param {Buffer} hashBytes
   * @param {string} [algorithm]
   * @returns {Promise<Buffer>}
   */
  async timestampHash(hashBytes, algorithm) {
    const algo = algorithm || this.digestAlgorithm;
    const digestOid = DIGEST_OID[algo];
    if (!digestOid) {
      throw new Error(`Unsupported algorithm: ${algo}`);
    }

    const requestBytes = buildTimestampRequest(hashBytes, digestOid);
    const responseBytes = await this._sendRequest(requestBytes);
    return responseBytes;
  }

  /**
   * Send timestamp request via HTTP.
   * @param {Buffer} requestBytes
   * @returns {Promise<Buffer>}
   */
  _sendRequest(requestBytes) {
    return new Promise((resolve, reject) => {
      const parsedUrl = url.parse(this.tsaUrl);
      const isHttps = parsedUrl.protocol === 'https:';
      const transport = isHttps ? https : http;

      const headers = {
        'Content-Type': 'application/timestamp-query',
        'Content-Transfer-Encoding': 'binary',
        'Content-Length': requestBytes.length
      };

      if (this.username && this.password) {
        const auth = Buffer.from(`${this.username}:${this.password}`).toString('base64');
        headers['Authorization'] = `Basic ${auth}`;
      }

      const req = transport.request({
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.path,
        method: 'POST',
        headers,
        timeout: this.timeout
      }, (res) => {
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => {
          if (res.statusCode !== 200) {
            reject(new Error(`TSA returned HTTP ${res.statusCode}`));
            return;
          }
          let body = Buffer.concat(chunks);
          const encoding = res.headers['content-transfer-encoding'];
          if (encoding && encoding.toLowerCase() === 'base64') {
            body = Buffer.from(body.toString('ascii'), 'base64');
          }
          resolve(body);
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      req.write(requestBytes);
      req.end();
    });
  }
}

module.exports = {
  TSAClient,
  DigestAlgorithm,
  computeHash,
  DIGEST_OID
};
