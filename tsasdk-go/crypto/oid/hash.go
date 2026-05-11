package oid

import (
	"crypto"
	"encoding/asn1"

	"github.com/diao2018/tsasdk/tsasdk-go/crypto/digest"
)

func ConvertToHash(alg asn1.ObjectIdentifier) (crypto.Hash, bool) {
	// Check SM3 first since it's not in the standard crypto.Hash
	if OIDDigestAlgorithmSM3.Equal(alg) {
		// Return SHA256 as a placeholder; callers should use digest package for SM3
		return crypto.SHA256, false
	}
	var hash crypto.Hash
	switch {
	case OIDDigestAlgorithmSHA1.Equal(alg):
		hash = crypto.SHA1
	case OIDDigestAlgorithmSHA256.Equal(alg):
		hash = crypto.SHA256
	case OIDDigestAlgorithmSHA384.Equal(alg):
		hash = crypto.SHA384
	case OIDDigestAlgorithmSHA512.Equal(alg):
		hash = crypto.SHA512
	default:
		return hash, false
	}
	return hash, hash.Available()
}

// IsSM3Algorithm checks if the given OID is the SM3 algorithm.
func IsSM3Algorithm(alg asn1.ObjectIdentifier) bool {
	return OIDDigestAlgorithmSM3.Equal(alg)
}

// ComputeSM3Hash computes the SM3 hash of the given message.
func ComputeSM3Hash(message []byte) ([]byte, error) {
	return digest.ComputeHashByAlgorithm(digest.SM3, message)
}
