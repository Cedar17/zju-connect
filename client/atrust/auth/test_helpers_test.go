package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
)

func newTLSTestSession(server *httptest.Server) *Session {
	transport := server.Client().Transport.(*http.Transport)
	return newSession(strings.TrimPrefix(server.URL, "https://"), transport.TLSClientConfig)
}
