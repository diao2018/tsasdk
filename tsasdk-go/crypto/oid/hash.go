package oid

import (
	"crypto"
	"encoding/asn1"
)

func ConvertToHash(alg asn1.ObjectIdentifier) (crypto.Hash, bool) {
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
