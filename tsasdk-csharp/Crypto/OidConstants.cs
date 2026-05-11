using System;

namespace SignDoc.TsaSdk.Crypto
{
    /// <summary>
    /// Supported digest algorithms.
    /// </summary>
    public enum DigestAlgorithm
    {
        SHA256,
        SHA384,
        SHA512,
        SM3
    }

    /// <summary>
    /// OID constants for digest algorithms and CMS structures.
    /// </summary>
    public static class OidConstants
    {
        public const string SHA256 = "2.16.840.1.101.3.4.2.1";
        public const string SHA384 = "2.16.840.1.101.3.4.2.2";
        public const string SHA512 = "2.16.840.1.101.3.4.2.3";
        public const string SM3 = "1.2.156.10197.1.401";

        public static string GetDigestOid(DigestAlgorithm algorithm)
        {
            return algorithm switch
            {
                DigestAlgorithm.SHA256 => SHA256,
                DigestAlgorithm.SHA384 => SHA384,
                DigestAlgorithm.SHA512 => SHA512,
                DigestAlgorithm.SM3 => SM3,
                _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
            };
        }
    }
}
