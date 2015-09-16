// Package storage implements signed URLs for Google Cloud Storage.
package storage

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// BucketObject identifies an bucket and object in Google Cloud Storage
// and is suitable for sending via JSON.
type BucketObject struct {
	Bucket string `json:"bucket"`
	Object string `json:"object"`
}

// PublicGetURL returns an HTTPS URL that can reference the given object name in this
// bucket. Note: this only works if the bucket and/or object is publicly readable.
func (bo *BucketObject) PublicGetURL() string {
	return "https://storage.googleapis.com/" + bo.Bucket + "/" + url.QueryEscape(bo.Object)
}

// SignedPutURL makes a URL which can be used to upload content to Google Cloud Storage
// by anyone with the URL.
// name is the name of the google cloud storage object
// contentType is the MIME of the content you can upload with the returned URL.
// contentMD5 is the an MD5 digest of the content you can upload with the returned URL.
// ttl (time to live) is the duration the signed URL is valid for.
func (bo *BucketObject) SignedPutURL(c context.Context, contentType, contentMD5 string, ttl time.Duration) (string, error) {
	md5, err := hex.DecodeString(contentMD5)
	if err != nil {
		return "", err
	}
	contentMD5Base64 := base64.StdEncoding.EncodeToString(md5)

	host := "https://storage.googleapis.com"
	resource := "/" + bo.Bucket + "/" + bo.Object
	expiry := time.Now().Add(ttl)
	return generateSignedURLs(c, host, resource, expiry, "PUT", contentMD5Base64, contentType)
}

// Taken from http://stackoverflow.com/a/26579165/196964 and
// https://cloud.google.com/storage/docs/access-control#Signed-URLs
func generateSignedURLs(c context.Context, host, resource string, expiry time.Time, httpVerb, contentMD5, contentType string) (string, error) {
	sa, err := appengine.ServiceAccount(c)
	if err != nil {
		return "", err
	}
	expiryStr := strconv.FormatInt(expiry.Unix(), 10)
	// The optional components should be the empty string.
	// https://cloud.google.com/storage/docs/access-control#Construct-the-String
	components := []string{
		httpVerb,    // PUT, GET, DELETE (but not POST)
		contentMD5,  // Optional. The MD5 digest value in base64. Client must provide same value if present.
		contentType, // Optional. Client must provide same value if present.
		expiryStr,   // Unix timestamp
		resource,    // /bucket/objectname
	}
	unsigned := strings.Join(components, "\n")
	_, b, err := appengine.SignBytes(c, []byte(unsigned))
	if err != nil {
		return "", err
	}
	sig := base64.StdEncoding.EncodeToString(b)
	p := url.Values{
		"GoogleAccessId": {sa},
		"Expires":        {expiryStr},
		"Signature":      {sig},
	}
	return fmt.Sprintf("%s%s?%s", host, resource, p.Encode()), err
}
