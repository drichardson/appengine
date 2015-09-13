package signedrequest

import (
	"google.golang.org/appengine/aetest"
	"testing"
	"time"
)

func TestSignedRequest(t *testing.T) {
	c, closer, err := aetest.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer closer()

	r := &SignedRequest{
		Method:     "POST",
		Url:        "https://howdy",
		Expiration: time.Now().Add(1 * time.Hour),
	}
	if err := r.Verify(c); err == nil {
		t.Fatal("Expected verify to fail before signing.")
	}
	if err := r.Sign(c); err != nil {
		t.Fatalf("Failed to sign. %v", err)
	}
	if err := r.Verify(c); err != nil {
		t.Fatalf("Expected signed request to verify. %v", err)
	}

	req, err := r.HTTPRequest(nil)
	if err != nil {
		t.Fatalf("Failed to create HTTP request. %v", err)
	}

	r2, err := ParseHTTPRequest(req)
	if err != nil {
		t.Fatalf("Failed to parse HTTP request. %v", err)
	}

	if err := r2.Verify(c); err != nil {
		t.Fatal("r2 failed to verify. %v", err)
	}

	// equality check... though note expiration times may be off by a fraction of a second. The
	// signature calcualtion, however, is based on the floor of the seconds.
	if r.Method != r2.Method || r.Url != r2.Url || r.Expiration.Unix() != r2.Expiration.Unix() || r.Signature != r2.Signature {
		t.Fatal("r1 != r2")
	}

	r.Expiration = time.Now().Add(-1 * time.Second)
	if err := r.Sign(c); err != nil {
		t.Fatalf("Failed to sign. %v", err)
	}
	if err := r.Verify(c); err != ErrExpired {
		t.Fatalf("Expected verification to fail with ErrExpired but got %v", err)
	}
}
