package tsp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	digest "github.com/tsasdk/tsasdk-go/crypto/digest"
	"github.com/tsasdk/tsasdk-go/crypto/oid"
	"math/big"
)

type Request struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      TSAPolicyID      `asn1:"optional"`
	Nonce          *big.Int         `asn1:"optional"`
	CertReq        bool             `asn1:"optional,default:false"`
	Extensions     []pkix.Extension `asn1:"optional,tag:0"`
}

func CreateRequest(digest digest.Digest) (*Request, error) {
	hashAlgorithm, found := oid.DigestAlgorithmOIDs[digest.Algorithm()]
	if !found {
		return nil, errors.New("Unknown algorithm")
	}
	hashedMessage, err := hex.DecodeString(digest.Encoded())
	if err != nil {
		return nil, err
	}

	return &Request{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: hashAlgorithm,
			},
			HashedMessage: hashedMessage,
		},
	}, nil
}

func (r *Request) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, errors.New("null request")
	}
	return asn1.Marshal(*r)
}

func (r *Request) UnmarshalBinary(data []byte) error {
	_, err := asn1.Unmarshal(data, r)
	return err
}

type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type TSAPolicyID = asn1.ObjectIdentifier
