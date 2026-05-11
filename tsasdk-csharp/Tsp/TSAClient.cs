using System;
using System.IO;
using System.Net;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Crypto.Digests;
using SignDoc.TsaSdk.Crypto;

namespace SignDoc.TsaSdk.Tsp
{
    /// <summary>
    /// RFC 3161 compliant TSA client.
    /// Supports SHA-256, SHA-384, SHA-512, and SM3 digest algorithms.
    /// </summary>
    public class TSAClient
    {
        private readonly string _tsaUrl;
        private readonly string _username;
        private readonly string _password;
        private readonly int _timeout;
        private readonly DigestAlgorithm _defaultAlgorithm;

        /// <summary>
        /// Create a new TSA client.
        /// </summary>
        /// <param name="tsaUrl">URL of the TSA server.</param>
        /// <param name="username">Username for Basic Auth (optional).</param>
        /// <param name="password">Password for Basic Auth (optional).</param>
        /// <param name="timeout">HTTP request timeout in milliseconds (default 8000).</param>
        /// <param name="defaultAlgorithm">Default digest algorithm (default SHA-256).</param>
        public TSAClient(
            string tsaUrl,
            string username = "",
            string password = "",
            int timeout = 8000,
            DigestAlgorithm defaultAlgorithm = DigestAlgorithm.SHA256)
        {
            _tsaUrl = tsaUrl ?? throw new ArgumentNullException(nameof(tsaUrl));
            _username = username ?? "";
            _password = password ?? "";
            _timeout = timeout;
            _defaultAlgorithm = defaultAlgorithm;
        }

        /// <summary>
        /// Request a timestamp token for the given data.
        /// </summary>
        /// <param name="data">The data to timestamp.</param>
        /// <param name="algorithm">Override the default digest algorithm.</param>
        /// <returns>The raw timestamp token bytes.</returns>
        public byte[] TimestampData(byte[] data, DigestAlgorithm? algorithm = null)
        {
            var algo = algorithm ?? _defaultAlgorithm;
            byte[] hash = HashUtil.ComputeHash(data, algo);
            return TimestampHash(hash, algo);
        }

        /// <summary>
        /// Request a timestamp token for a pre-computed hash.
        /// </summary>
        /// <param name="hashBytes">The pre-computed hash digest.</param>
        /// <param name="algorithm">The algorithm used to compute the hash.</param>
        /// <returns>The raw timestamp token bytes.</returns>
        public byte[] TimestampHash(byte[] hashBytes, DigestAlgorithm? algorithm = null)
        {
            var algo = algorithm ?? _defaultAlgorithm;
            string digestOid = OidConstants.GetDigestOid(algo);

            // Build TimeStampRequest
            var requestGenerator = new TimeStampRequestGenerator();
            requestGenerator.SetCertReq(true);

            var nonce = BigInteger.ValueOf(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            var asn1Oid = new DerObjectIdentifier(digestOid);
            var request = requestGenerator.Generate(asn1Oid, hashBytes, nonce);
            byte[] requestBytes = request.GetEncoded();

            // Send to TSA
            byte[] responseBytes = GetTSAResponse(requestBytes);

            // Parse response
            var response = new TimeStampResponse(responseBytes);

            if (response.GetFailInfo() != null)
            {
                throw new Exception($"TSA returned failure: {response.GetFailInfo()}");
            }

            TimeStampToken token = response.TimeStampToken;
            if (token == null)
            {
                throw new Exception("TSA failed to return time stamp token");
            }

            return token.GetEncoded();
        }

        /// <summary>
        /// Extract the timestamp time from a token.
        /// </summary>
        /// <param name="tokenBytes">The raw timestamp token bytes.</param>
        /// <returns>The generation time as a string.</returns>
        public string GetTime(byte[] tokenBytes)
        {
            var tsToken = new TimeStampToken(new Org.BouncyCastle.Cms.CmsSignedData(tokenBytes));
            return tsToken.TimeStampInfo.GenTime.ToString("yyyy-MM-dd HH:mm:ss");
        }

        private byte[] GetTSAResponse(byte[] requestBytes)
        {
            var request = (HttpWebRequest)WebRequest.Create(_tsaUrl);
            request.Method = "POST";
            request.ContentType = "application/timestamp-query";
            request.Timeout = _timeout;
            request.ContentLength = requestBytes.Length;

            // Basic Auth
            if (!string.IsNullOrEmpty(_username))
            {
                string auth = Convert.ToBase64String(
                    Encoding.UTF8.GetBytes($"{_username}:{_password}"));
                request.Headers.Add("Authorization", $"Basic {auth}");
            }

            using (var stream = request.GetRequestStream())
            {
                stream.Write(requestBytes, 0, requestBytes.Length);
            }

            using (var response = (HttpWebResponse)request.GetResponse())
            {
                if (response.StatusCode != HttpStatusCode.OK)
                {
                    throw new Exception($"TSA returned HTTP {(int)response.StatusCode}");
                }

                using (var ms = new MemoryStream())
                {
                    response.GetResponseStream().CopyTo(ms);
                    byte[] respBytes = ms.ToArray();

                    string encoding = response.Headers["Content-Transfer-Encoding"];
                    if (encoding != null && encoding.Equals("base64", StringComparison.OrdinalIgnoreCase))
                    {
                        respBytes = Convert.FromBase64String(Encoding.ASCII.GetString(respBytes));
                    }

                    return respBytes;
                }
            }
        }
    }
}
