package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/config"
)

func TestNewOIDC_UsesBoundedHTTPClient(t *testing.T) {
	_, s := newTestWeb(t)
	idp := setupOIDCServer(t)
	o := newOIDCFromMock(t, idp, s, config.OIDCConfig{})

	if o.httpClient == nil {
		t.Fatal("NewOIDC configured no HTTP client")
	}
	if o.httpClient.Timeout != oidcHTTPTimeout {
		t.Fatalf("HTTP timeout = %v, want %v", o.httpClient.Timeout, oidcHTTPTimeout)
	}
}

func TestOIDCHTTPClient_TimeoutsSilentProvider(t *testing.T) {
	requestStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-r.Context().Done()
	}))
	defer server.Close()

	client, err := newOIDCHTTPClient("", 20*time.Millisecond)
	if err != nil {
		t.Fatalf("newOIDCHTTPClient: %v", err)
	}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	_, err = client.Do(request)
	if err == nil {
		t.Fatal("request to silent provider succeeded; want timeout")
	}
	select {
	case <-requestStarted:
	default:
		t.Fatal("silent provider never received the request")
	}
}
