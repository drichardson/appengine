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

// Verify a signature produced by appengine.SignBytes. c must be a context.Context
// created from appengine.Context.
// The implementation of this method comes from investigation to answer this question:
// http://stackoverflow.com/questions/32486427/how-do-you-verify-the-signature-returned-by-appengine-signbytes
func VerifyBytes(c context.Context, bytes []byte, sig []byte) error {
	certs, err := appengine.PublicCertificates(c)
	if err != nil {
		log.Errorf(c, "Error getting public certificates. %v", err)
		return err
	}

	lastErr := errors.New("ErrNoPublicCertificates")

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
		signBytesHash := crypto.SHA256
		h := signBytesHash.New()
		h.Write(bytes)
		hashed := h.Sum(nil)
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
