// Package googleapiclient implements an http.Client that allow App Engine intances
// to use the Google API Client library. For more information, see https://github.com/google/google-api-go-client.
package googleapiclient

import (
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/appengine/urlfetch"
	"net/http"
)

// NewClient returns an http.Client that can be used to create services from the
// Google APIs for Go library https://github.com/google/google-api-go-client.
// The scopes parameter is used to declare the OAuth 2
// scopes, e.g., storage.DevstorageFullControlScope.
func NewClient(c context.Context, scopes ...string) *http.Client {
	return &http.Client{
		Transport: &oauth2.Transport{
			Source: google.AppEngineTokenSource(c, scopes...),
			// Note that the App Engine urlfetch service has a limit of 10MB uploads and
			// 32MB downloads.
			// See https://cloud.google.com/appengine/docs/go/urlfetch/#Go_Quotas_and_limits
			// for more information.
			Base: &urlfetch.Transport{Context: c},
		},
	}
}
