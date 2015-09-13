// Package signature verifies signatures created by the App Engine runtime's
// appengine.SignBytes function.
package signature

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
)

// Error codes returned by verification failures.
var (
	ErrNoPublicCertificates = errors.New("ErrNoPublicCertificates")
	ErrPemDecodeFailure     = errors.New("ErrPemDecodeFailure")
	ErrNotRSAPublicKey      = errors.New("ErrNotRSAPublicKey")
)

// VerifyBytes verifies a signature produced by appengine.SignBytes. c must be a
// context.Context created from appengine.NewContext.
func VerifyBytes(c context.Context, bytes []byte, sig []byte) error {
	certs, err := appengine.PublicCertificates(c)
	if err != nil {
		return err
	}

	lastErr := ErrNoPublicCertificates

	signBytesHash := crypto.SHA256
	h := signBytesHash.New()
	h.Write(bytes)
	hashed := h.Sum(nil)

	for _, cert := range certs {
		block, _ := pem.Decode(cert.Data)
		if block == nil {
			lastErr = ErrPemDecodeFailure
			continue
		}
		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			lastErr = err
			continue
		}
		pubkey, ok := x509Cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			lastErr = ErrNotRSAPublicKey
			continue
		}
		err = rsa.VerifyPKCS1v15(pubkey, signBytesHash, hashed, sig)
		if err != nil {
			lastErr = err
			continue
		}

		return nil
	}

	return lastErr
}
