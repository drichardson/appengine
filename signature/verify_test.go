package signature

import (
	"google.golang.org/appengine"
	"google.golang.org/appengine/aetest"
	"testing"
)

func TestSignatureVerification(t *testing.T) {
	c, closer, err := aetest.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer closer()

	data := []byte("hello, world!")
	_, sig, err := appengine.SignBytes(c, data)
	if err != nil {
		t.Fatalf("Error signing data. %v", err)
	}

	if err := VerifyBytes(c, data, sig); err != nil {
		t.Fatalf("Expected verification to succeed, but if failed. %v", err)
	}

	data2 := []byte("hello, world!!")
	if err := VerifyBytes(c, data2, sig); err == nil {
		t.Fatalf("Expected verification to fail, but if succeeded")
	}
}
