package tsp

import (
	"encoding/asn1"
	"errors"
	"github.com/tsasdk/tsasdk-go/crypto/pki"
)

type Response struct {
	Status         pki.StatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

func (r *Response) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil response")
	}
	return asn1.Marshal(r)
}

func (r *Response) UnmarshalBinary(data []byte) error {
	_, err := asn1.Unmarshal(data, r)
	return err
}

func (r *Response) TokenBytes() []byte {
	return r.TimeStampToken.FullBytes
}

func (r *Response) SignedToken() (*SignedToken, error) {
	return ParseSignedToken(r.TokenBytes())
}
