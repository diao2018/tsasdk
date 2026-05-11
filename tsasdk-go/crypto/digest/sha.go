package digest

import (
	"crypto"
	"hash"

	// make sure crypto.SHA256 is registered
	_ "crypto/sha256"

	// make sure crypto.sha512 and crypto.SHA384 are registered
	_ "crypto/sha512"
)

const (
	SHA256 Algorithm = "sha256" // sha256 with hex encoding (lower case only)
	SHA384 Algorithm = "sha384" // sha384 with hex encoding (lower case only)
	SHA512 Algorithm = "sha512" // sha512 with hex encoding (lower case only)
	SM3    Algorithm = "sm3"    // SM3 (GB/T 32905-2016) with hex encoding
)

func init() {
	RegisterAlgorithm(SHA256, crypto.SHA256)
	RegisterAlgorithm(SHA384, crypto.SHA384)
	RegisterAlgorithm(SHA512, crypto.SHA512)
	RegisterAlgorithm(SM3, sm3CryptoHash{})
}

// sm3CryptoHash implements the CryptoHash interface for SM3.
type sm3CryptoHash struct{}

func (sm3CryptoHash) Available() bool { return true }
func (sm3CryptoHash) Size() int       { return 32 }
func (sm3CryptoHash) New() hash.Hash {
	return NewSM3()
}
