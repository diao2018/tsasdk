package tsp

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	asn1util "github.com/tsasdk/tsasdk-go/asn1"
	"github.com/tsasdk/tsasdk-go/crypto/cms"
	"github.com/tsasdk/tsasdk-go/crypto/digest"
	"github.com/tsasdk/tsasdk-go/crypto/oid"
	"math/big"
	"time"
)

type SignedToken cms.ParsedSignedData

func ParseSignedToken(data []byte) (*SignedToken, error) {
	data, err := asn1util.ConvertToDER(data)
	if err != nil {
		return nil, err
	}
	signed, err := cms.ParseSignedData(data)
	if err != nil {
		return nil, err
	}
	if !oid.OIDCTTSTInfo.Equal(signed.ContentType) {
		return nil, fmt.Errorf("unexpected content type: %v", signed.ContentType)
	}
	return (*SignedToken)(signed), nil
}

func (t *SignedToken) Verify(opts x509.VerifyOptions) ([]*x509.Certificate, error) {
	if len(opts.KeyUsages) == 0 {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	}
	signed := (*cms.ParsedSignedData)(t)
	certs, err := signed.Verify(opts)
	if err != nil {
		return nil, err
	}

	// RFC 3161 2.3: The corresponding certificate MUST contain only one instance of
	// the extended key usage field extension.
	verifiedCerts := make([]*x509.Certificate, 0, len(certs))
	for _, cert := range certs {
		if len(cert.ExtKeyUsage) == 1 && len(cert.UnknownExtKeyUsage) == 0 {
			verifiedCerts = append(verifiedCerts, cert)
		}
	}
	if len(verifiedCerts) == 0 {
		return nil, errors.New("unexpected number of extended key usages")
	}
	return verifiedCerts, nil
}

func (t *SignedToken) Info() (*TSTInfo, error) {
	var info TSTInfo
	if _, err := asn1.Unmarshal(t.Content, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

type Accuracy struct {
	Seconds      int `asn1:"optional"`
	Milliseconds int `asn1:"optional,tag:0"`
	Microseconds int `asn1:"optional,tag:1"`
}

type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       Accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional,tag:0"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

func (tst *TSTInfo) VerifyContent(message []byte) error {
	hashAlg := tst.MessageImprint.HashAlgorithm.Algorithm
	hash, ok := oid.ConvertToHash(hashAlg)
	if !ok {
		return fmt.Errorf("unrecognized hash algorithm: %v", hashAlg)
	}

	messageDigest, err := digest.ComputeHash(hash, message)
	if err != nil {
		return err
	}

	return tst.Verify(messageDigest)
}

func (tst *TSTInfo) Verify(messageDigest []byte) error {
	if !bytes.Equal(tst.MessageImprint.HashedMessage, messageDigest) {
		return errors.New("mismatch message digest")
	}
	return nil
}

func (tst *TSTInfo) Timestamp() (time.Time, time.Duration) {
	accuracy := time.Duration(tst.Accuracy.Seconds)*time.Second +
		time.Duration(tst.Accuracy.Milliseconds)*time.Millisecond +
		time.Duration(tst.Accuracy.Microseconds)*time.Microsecond
	return tst.GenTime, accuracy
}
