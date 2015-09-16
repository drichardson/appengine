package signedrequest

import (
	"google.golang.org/appengine"
	"net/http"
)

// SignedHandlerFunc is like http.HandlerFunc, but also takes SignedRequest
// as the last parameter. This method is only called by ServeHTTP if the
// the signature is valid.
type HandlerFunc func(http.ResponseWriter, *http.Request, *SignedRequest)

// ServeHTTP implements the http.Handler interface. If the request signature is valid, the
// HandlerFunc is invoked.
func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	signedRequest, err := ParseHTTPRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Not a valid signed request."))
		return
	}
	err = signedRequest.Verify(c)
	if err != nil {
		if err == ErrExpired {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Signed URL expired."))
			return
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	f(w, r, signedRequest)
}
