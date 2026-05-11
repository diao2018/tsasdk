"""
ASN.1 DER encoding utilities for RFC 3161 timestamp requests.
"""

import struct


def _encode_length(length: int) -> bytes:
    """Encode length in DER format."""
    if length < 0x80:
        return bytes([length])
    # Long form
    length_bytes = []
    n = length
    while n > 0:
        length_bytes.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(length_bytes)] + length_bytes)


def _encode_oid(oid_string: str) -> bytes:
    """Encode an OID string (e.g. '2.16.840.1.101.3.4.2.1') into DER bytes."""
    components = list(map(int, oid_string.split(".")))
    if len(components) < 2:
        raise ValueError("OID must have at least 2 components")

    encoded = []
    # First two components: first * 40 + second
    encoded.append(components[0] * 40 + components[1])

    for comp in components[2:]:
        if comp == 0:
            encoded.append(0)
        else:
            # Base-128 encoding
            parts = []
            val = comp
            parts.insert(0, val & 0x7F)
            val >>= 7
            while val > 0:
                parts.insert(0, 0x80 | (val & 0x7F))
                val >>= 7
            encoded.extend(parts)

    return bytes(encoded)


def _encode_integer(value: int) -> bytes:
    """Encode an integer in DER format."""
    if value == 0:
        return b'\x00'
    result = []
    n = value
    while n > 0:
        result.insert(0, n & 0xFF)
        n >>= 8
    # Add leading zero if high bit is set
    if result[0] & 0x80:
        result.insert(0, 0)
    return bytes(result)


def _encode_octet_string(data: bytes) -> bytes:
    """Encode an OCTET STRING in DER format."""
    return b'\x04' + _encode_length(len(data)) + data


def _encode_bit_string(data: bytes, unused_bits: int = 0) -> bytes:
    """Encode a BIT STRING in DER format."""
    content = bytes([unused_bits]) + data
    return b'\x03' + _encode_length(len(content)) + content


def _encode_boolean(value: bool) -> bytes:
    """Encode a BOOLEAN in DER format."""
    return b'\x01\x01' + (b'\xFF' if value else b'\x00')


def _encode_sequence(content: bytes) -> bytes:
    """Encode a SEQUENCE in DER format."""
    return b'\x30' + _encode_length(len(content)) + content


def _encode_set(content: bytes) -> bytes:
    """Encode a SET in DER format."""
    return b'\x31' + _encode_length(len(content)) + content


def _encode_explicit_tag(tag_number: int, content: bytes) -> bytes:
    """Encode an EXPLICIT context-specific tag."""
    tag = 0xA0 | tag_number
    return bytes([tag]) + _encode_length(len(content)) + content


def _encode_null() -> bytes:
    """Encode NULL in DER format."""
    return b'\x05\x00'


def encode_algorithm_identifier(oid_string: str) -> bytes:
    """Encode an AlgorithmIdentifier SEQUENCE { algorithm OID, parameters NULL }."""
    oid_bytes = _encode_oid(oid_string)
    oid_tlv = b'\x06' + _encode_length(len(oid_bytes)) + oid_bytes
    return _encode_sequence(oid_tlv + _encode_null())


def encode_message_imprint(hash_bytes: bytes, digest_oid: str) -> bytes:
    """Encode MessageImprint SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }."""
    algo_id = encode_algorithm_identifier(digest_oid)
    hashed_msg = _encode_octet_string(hash_bytes)
    return _encode_sequence(algo_id + hashed_msg)


def encode_timestamp_request(hash_bytes: bytes, digest_oid: str, cert_req: bool = True, nonce: int = None) -> bytes:
    """
    Encode a full RFC 3161 TimeStampReq.

    TimeStampReq ::= SEQUENCE {
        version          INTEGER { v1(1) },
        messageImprint   MessageImprint,
        reqPolicy        TSAPolicyId OPTIONAL,
        nonce            INTEGER OPTIONAL,
        certReq          BOOLEAN DEFAULT FALSE,
        extensions       [0] IMPLICIT Extensions OPTIONAL
    }
    """
    # version = 1
    version = b'\x02\x01\x01'

    # messageImprint
    message_imprint = encode_message_imprint(hash_bytes, digest_oid)

    content = version + message_imprint

    # nonce
    if nonce is None:
        import time
        nonce = int(time.time() * 1000)
    nonce_bytes = _encode_integer(nonce)
    content += b'\x02' + _encode_length(len(nonce_bytes)) + nonce_bytes

    # certReq
    if cert_req:
        content += _encode_boolean(True)

    return _encode_sequence(content)
