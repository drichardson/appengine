package signedrequest

import (
	"google.golang.org/appengine"
	"google.golang.org/appengine/aetest"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandler(t *testing.T) {

	inst, err := aetest.NewInstance(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()

	var handlerFunc HandlerFunc = func(w http.ResponseWriter, r *http.Request, sr *SignedRequest) {
		w.WriteHeader(http.StatusOK)
	}

	// assign to http.Handler to make sure interface implemented
	var handler http.Handler = handlerFunc

	// try an unsigned request, should get bad request
	req, err := inst.NewRequest("PUT", "/", nil)
	if err != nil {
		t.Fatalf("NewRequest failed %v", err)
	}
	rr := &httptest.ResponseRecorder{}
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected bad request, got %v", rr.Code)
	}

	// try a signed request, should work
	sr := &SignedRequest{
		Method:     "PUT",
		URL:        "/",
		Expiration: time.Now().Add(1 * time.Minute),
	}
	c := appengine.NewContext(req)
	sr.Sign(c)
	err = sr.Sign(c)
	if err != nil {
		t.Fatalf("Error singing %v", err)
	}
	req, err = testRequestFromSignedRequest(inst, sr)
	if err != nil {
		t.Fatalf("failed to get request %v", err)
	}
	rr = &httptest.ResponseRecorder{}
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected ok, got %v", rr.Code)
	}

	// try a signed request that's expired, should get bad request
	sr = &SignedRequest{
		Method:     "PUT",
		URL:        "/",
		Expiration: time.Now().Add(-1 * time.Second), // expired
	}
	c = appengine.NewContext(req)
	sr.Sign(c)
	err = sr.Sign(c)
	if err != nil {
		t.Fatalf("Error singing %v", err)
	}
	req, err = testRequestFromSignedRequest(inst, sr)
	if err != nil {
		t.Fatalf("failed to get request %v", err)
	}
	rr = &httptest.ResponseRecorder{}
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected bad request, got %v", rr.Code)
	}
}

func testRequestFromSignedRequest(inst aetest.Instance, sr *SignedRequest) (*http.Request, error) {
	srReq, err := sr.HTTPRequest(nil)
	if err != nil {
		return nil, err
	}
	req, err := inst.NewRequest(srReq.Method, srReq.URL.String(), srReq.Body)
	if err != nil {
		return nil, err
	}
	for k, vals := range srReq.Header {
		req.Header[k] = vals
	}

	return req, nil
}
