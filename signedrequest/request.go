// Package signedrequest provides supports for generating signed HTTP requests
// with expirations on App Engine.
package signedrequest

import (
	"encoding/base64"
	"errors"
	"github.com/drichardson/appengine/signature"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SignedRequest contains request parameters, an expiration, and signature.
// Method, URL, and Expiration should be set by the user.
// Headers are optional. Signature is set by the Sign function. All
// the fields (except Signature) are signed by the Sign function.
type SignedRequest struct {
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Expiration time.Time   `json:"expiration"`
	Headers    http.Header `json:"headers"`
	Signature  string      `json:"signature"`
}

// Sign signs the request parameters and sets the Signature field.
// c must be an App Engine context created with appengine.NewContext.
func (p *SignedRequest) Sign(c context.Context) error {
	_, sig, err := appengine.SignBytes(c, []byte(p.signingString()))
	if err != nil {
		return err
	}
	p.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Error code that indicates the request signature has expired.
var ErrExpired = errors.New("ErrExpired")

// Verify verifies the request signature. c must be an appengine context
// created with appengine.NewContext.
func (p *SignedRequest) Verify(c context.Context) error {
	sig, err := base64.StdEncoding.DecodeString(p.Signature)
	if err != nil {
		return err
	}
	err = signature.VerifyBytes(c, []byte(p.signingString()), sig)
	if err != nil {
		return err
	}
	if time.Now().After(p.Expiration) {
		return ErrExpired
	}
	return nil
}

// signingString creates a canonical string out of the SignedRequest
// suitable for signing (meaning the same string is always produces
// from the same input). Care must be taken with times with fractional
// seconds and also headers which are stored in a map, which Go explicially
// gaurentees will not be iterated through in the same order.
// See http://golang.org/ref/spec#RangeClause for information on range and map.
func (p *SignedRequest) signingString() string {
	// Sort headers by CanonicalHeaderKey to have a consistent sort, even if transformed
	// by intermediate http proxies.
	sortedHeaders := make([]string, 0, len(p.Headers))
	for k, v := range p.Headers {
		sortedHeaders = append(sortedHeaders, http.CanonicalHeaderKey(k)+": "+strings.Join(v, ","))
	}
	sort.Strings(sortedHeaders)

	// The method and url are case-sensitive, so don't transform them.
	// http://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html
	// Use a UNIX time, since there are multiple equivalent representations
	// of RFC 3339 time, but we want to treat them all as the same for signing purposes.
	components := []string{
		p.Method,
		p.URL,
		strconv.FormatInt(p.Expiration.Unix(), 10),
	}
	components = append(components, sortedHeaders...)

	return strings.Join(components, "\n")
}

// HTTPRequest creates an http.Request from the SignedRequest.
// The body is not part of the signature.
func (p *SignedRequest) HTTPRequest(body io.Reader) (*http.Request, error) {
	r, err := http.NewRequest(p.Method, p.URL, body)
	if err != nil {
		return nil, err
	}
	signedHeaders := []string{}
	for k, vals := range p.Headers {
		signedHeaders = append(signedHeaders, k)
		for _, v := range vals {
			r.Header.Add(k, v)
		}
	}
	r.Header.Set("Signature", p.Signature)
	r.Header.Set("Signature-Expiration", p.Expiration.Format(time.RFC3339))
	r.Header[http.CanonicalHeaderKey("Signed-Headers")] = signedHeaders
	return r, nil
}

// ParseHTTPRequest parses the SignedRequest from an http.Request
// created with HTTPRequest.
func ParseHTTPRequest(r *http.Request) (*SignedRequest, error) {

	signature := r.Header.Get("Signature")
	expirationStr := r.Header.Get("Signature-Expiration")
	signedHeaderKeys, _ := r.Header[http.CanonicalHeaderKey("Signed-Headers")]

	expiration, err := time.Parse(time.RFC3339, expirationStr)
	if err != nil {
		return nil, err
	}

	signedHeaders := make(http.Header)
	for _, key := range signedHeaderKeys {
		signedHeaders[key] = r.Header[http.CanonicalHeaderKey(key)]
	}

	p := &SignedRequest{
		Method:     r.Method,
		URL:        r.URL.String(),
		Expiration: expiration,
		Headers:    signedHeaders,
		Signature:  signature,
	}

	return p, nil
}
