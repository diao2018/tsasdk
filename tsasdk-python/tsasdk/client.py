"""
RFC 3161 TSA Client with SM3 support.
"""

import base64
import urllib.request
import urllib.error
from typing import Optional

from .crypto.digest import DigestAlgorithm, compute_hash, DIGEST_OID_MAP
from .crypto.asn1utils import encode_timestamp_request


class TSAClient:
    """
    RFC 3161 compliant TSA (Time Stamp Authority) client.

    Supports SHA-256, SHA-384, SHA-512, and SM3 hash algorithms.
    """

    def __init__(
        self,
        tsa_url: str,
        username: str = "",
        password: str = "",
        timeout: int = 10,
        digest_algorithm: DigestAlgorithm = DigestAlgorithm.SHA256,
    ):
        """
        Initialize TSA client.

        Args:
            tsa_url: URL of the TSA server.
            username: Username for Basic Auth (optional).
            password: Password for Basic Auth (optional).
            timeout: HTTP request timeout in seconds.
            digest_algorithm: Default digest algorithm.
        """
        self.tsa_url = tsa_url
        self.username = username
        self.password = password
        self.timeout = timeout
        self.digest_algorithm = digest_algorithm

    def timestamp(
        self,
        data: bytes,
        digest_algorithm: Optional[DigestAlgorithm] = None,
        cert_req: bool = True,
    ) -> bytes:
        """
        Request a timestamp token for the given data.

        Args:
            data: The data to timestamp.
            digest_algorithm: Override the default digest algorithm.
            cert_req: Whether to request the TSA certificate.

        Returns:
            The raw timestamp token bytes.
        """
        algo = digest_algorithm or self.digest_algorithm
        hash_bytes = compute_hash(data, algo)
        return self.timestamp_hash(hash_bytes, algo, cert_req=cert_req)

    def timestamp_hash(
        self,
        hash_bytes: bytes,
        digest_algorithm: Optional[DigestAlgorithm] = None,
        cert_req: bool = True,
    ) -> bytes:
        """
        Request a timestamp token for a pre-computed hash.

        Args:
            hash_bytes: The pre-computed hash digest.
            digest_algorithm: The algorithm used to compute the hash.
            cert_req: Whether to request the TSA certificate.

        Returns:
            The raw timestamp token bytes.
        """
        algo = digest_algorithm or self.digest_algorithm
        digest_oid = DIGEST_OID_MAP[algo]

        # Build RFC 3161 request
        request_der = encode_timestamp_request(hash_bytes, digest_oid, cert_req=cert_req)

        # Send HTTP request
        response_bytes = self._send_request(request_der)

        return response_bytes

    def _send_request(self, request_bytes: bytes) -> bytes:
        """
        Send timestamp request to TSA server via HTTP.

        Args:
            request_bytes: DER-encoded TimeStampReq.

        Returns:
            DER-encoded TimeStampResp.
        """
        req = urllib.request.Request(
            self.tsa_url,
            data=request_bytes,
            headers={
                "Content-Type": "application/timestamp-query",
                "Content-Transfer-Encoding": "binary",
            },
            method="POST",
        )

        if self.username and self.password:
            credentials = f"{self.username}:{self.password}"
            encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
            req.add_header("Authorization", f"Basic {encoded}")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"TSA returned HTTP {resp.status}: {resp.reason}")
                content_type = resp.headers.get("Content-Type", "")
                response_bytes = resp.read()

                # Handle base64-encoded responses
                content_transfer = resp.headers.get("Content-Transfer-Encoding", "")
                if content_transfer.lower() == "base64":
                    response_bytes = base64.b64decode(response_bytes)

                return response_bytes
        except urllib.error.URLError as e:
            raise RuntimeError(f"Failed to connect to TSA at {self.tsa_url}: {e}") from e

    @staticmethod
    def timestamp_file(
        filepath: str,
        tsa_url: str,
        username: str = "",
        password: str = "",
        digest_algorithm: DigestAlgorithm = DigestAlgorithm.SHA256,
    ) -> bytes:
        """
        Convenience method: hash a file and request a timestamp.

        Args:
            filepath: Path to the file.
            tsa_url: URL of the TSA server.
            username: Username for Basic Auth.
            password: Password for Basic Auth.
            digest_algorithm: Hash algorithm.

        Returns:
            The raw timestamp token bytes.
        """
        from .crypto.digest import compute_hash_for_file
        client = TSAClient(tsa_url, username, password, digest_algorithm=digest_algorithm)
        hash_bytes = compute_hash_for_file(filepath, digest_algorithm)
        return client.timestamp_hash(hash_bytes, digest_algorithm)
