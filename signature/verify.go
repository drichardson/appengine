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
	"google.golang.org/appengine/log"
)

var ErrNoPublicCertificates = errors.New("ErrNoPublicCertificates")

// Verify a signature produced by appengine.SignBytes. c must be a context.Context
// created from appengine.Context.
func VerifyBytes(c context.Context, bytes []byte, sig []byte) error {
	certs, err := appengine.PublicCertificates(c)
	if err != nil {
		log.Errorf(c, "Error getting public certificates. %v", err)
		return err
	}

	lastErr := ErrNoPublicCertificates

	signBytesHash := crypto.SHA256
	h := signBytesHash.New()
	h.Write(bytes)
	hashed := h.Sum(nil)

	for i, cert := range certs {
		block, _ := pem.Decode(cert.Data)
		if block == nil {
			log.Errorf(c, "Failed to decode certificate %v", i)
			lastErr = errors.New("ErrPemDecodeFailure")
			continue
		}
		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Errorf(c, "Error parsing x509 certificate. %v", err)
			lastErr = err
			continue
		}
		pubkey, ok := x509Cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			log.Errorf(c, "Type assertion failed to convert public key to rsa.PublicKey")
			lastErr = errors.New("ErrNotRSAPublicKey")
			continue
		}
		err = rsa.VerifyPKCS1v15(pubkey, signBytesHash, hashed, sig)
		if err != nil {
			log.Debugf(c, "Failed to verify signature with key %v named %v", i, cert.KeyName)
			lastErr = err
			continue
		}

		return nil
	}

	return lastErr
}
