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

type SignedRequest struct {
	Method        string      `json:"method"`
	Url           string      `json:"url"`
	Expiration    time.Time   `json:"expiration"`
	SignedHeaders http.Header `json:"signed_headers"`
	Signature     string      `json:"signature"`
}

// Sign the parameters. This sets the Signature field. c must be an appengine context.
func (p *SignedRequest) Sign(c context.Context) error {
	_, sig, err := appengine.SignBytes(c, []byte(p.signingString()))
	if err != nil {
		return err
	}
	p.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

var ErrExpired = errors.New("ErrExpired")

// Verify a request is valid. c must be an appengine context.
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

func (p *SignedRequest) signingString() string {
	// Sort headers by CanonicalHeaderKey to have a consistent sort, even if transformed
	// by intermediate http proxies.
	sortedHeaders := make([]string, 0, len(p.SignedHeaders))
	for k, v := range p.SignedHeaders {
		sortedHeaders = append(sortedHeaders, http.CanonicalHeaderKey(k)+": "+strings.Join(v, ","))
	}
	sort.Strings(sortedHeaders)

	// The method and url are case-sensitive, so don't transform them.
	// http://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html
	// Use a UNIX time, since there are multiple equivalent representations
	// of RFC 3339 time, but we want to treat them all as the same for signing purposes.
	components := []string{
		p.Method,
		p.Url,
		strconv.FormatInt(p.Expiration.Unix(), 10),
	}
	components = append(components, sortedHeaders...)

	return strings.Join(components, "\n")
}

// Create an http.Request from the SignedRequest. Note, the body is not signed.
func (p *SignedRequest) HTTPRequest(body io.Reader) (*http.Request, error) {
	r, err := http.NewRequest(p.Method, p.Url, body)
	if err != nil {
		return nil, err
	}
	signedHeaders := []string{}
	for k, vals := range p.SignedHeaders {
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

// Get the SignedRequest from an http.Request created with HTTPRequest.
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
		Method:        r.Method,
		Url:           r.URL.String(),
		Expiration:    expiration,
		SignedHeaders: signedHeaders,
		Signature:     signature,
	}

	return p, nil
}
