using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto;

namespace SignDoc.TsaSdk.Crypto
{
    /// <summary>
    /// Hash computation utilities supporting SHA-256, SHA-384, SHA-512, and SM3.
    /// </summary>
    public static class HashUtil
    {
        /// <summary>
        /// Compute hash of the given data.
        /// </summary>
        public static byte[] ComputeHash(byte[] data, DigestAlgorithm algorithm)
        {
            IDigest digest = CreateDigest(algorithm);
            digest.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }

        /// <summary>
        /// Compute hash of a string using UTF-8 encoding.
        /// </summary>
        public static byte[] ComputeHash(string text, DigestAlgorithm algorithm)
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes(text);
            return ComputeHash(data, algorithm);
        }

        /// <summary>
        /// Create an IDigest instance for the given algorithm.
        /// </summary>
        public static IDigest CreateDigest(DigestAlgorithm algorithm)
        {
            return algorithm switch
            {
                DigestAlgorithm.SHA256 => new Sha256Digest(),
                DigestAlgorithm.SHA384 => new Sha384Digest(),
                DigestAlgorithm.SHA512 => new Sha512Digest(),
                DigestAlgorithm.SM3 => new SM3Digest(),
                _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
            };
        }
    }
}
