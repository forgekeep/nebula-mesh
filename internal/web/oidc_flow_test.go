package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestOIDC_FlowCookieIsBoundAndExpires(t *testing.T) {
	cipher, err := newOIDCFlowCipher()
	if err != nil {
		t.Fatal(err)
	}
	o := &OIDC{flowCipher: cipher}
	now := time.Now()
	flow, err := newOIDCFlow(now)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := o.sealFlow(flow)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/ui/oidc/callback?state="+flow.State, nil)
	req.AddCookie(&http.Cookie{Name: o.flowCookieName(), Value: sealed})
	got, err := o.readFlow(req, flow.State, now)
	if err != nil || got != flow {
		t.Fatalf("readFlow = %#v, %v, want %#v", got, err, flow)
	}
	if _, err := o.readFlow(req, flow.State, now.Add(oidcFlowTTL)); err == nil {
		t.Fatal("expired flow cookie was accepted")
	}

	req.AddCookie(&http.Cookie{Name: o.flowCookieName(), Value: sealed + "tampered"})
	if _, err := o.readFlow(req, flow.State, now); err == nil {
		t.Fatal("tampered flow cookie was accepted")
	}
}

func TestOIDC_HandleLoginSetsBoundedHttpOnlyCookieWithoutStorage(t *testing.T) {
	cipher, err := newOIDCFlowCipher()
	if err != nil {
		t.Fatal(err)
	}
	o := &OIDC{
		flowCipher: cipher,
		oauth: &oauth2.Config{
			ClientID:    "client",
			RedirectURL: "https://nebula-mesh.test/ui/oidc/callback",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.test/authorize"},
		},
	}
	rec := httptest.NewRecorder()
	o.HandleLogin(rec, httptest.NewRequest(http.MethodGet, "/ui/oidc/login", nil))
	if rec.Code != 303 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("login response = %d, cache-control %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != oidcFlowCookie || !cookie.HttpOnly || cookie.Secure || cookie.SameSite != http.SameSiteLaxMode ||
		cookie.Path != "/" || cookie.MaxAge != int(oidcFlowTTL.Seconds()) {
		t.Fatalf("flow cookie attributes = %#v", cookie)
	}
	location := rec.Header().Get("Location")
	for _, parameter := range []string{"code_challenge=", "code_challenge_method=S256", "nonce="} {
		if !strings.Contains(location, parameter) {
			t.Errorf("authorization URL %q lacks %q", location, parameter)
		}
	}

	o.SetCookieSecure(true)
	rec = httptest.NewRecorder()
	o.HandleLogin(rec, httptest.NewRequest(http.MethodGet, "/ui/oidc/login", nil))
	cookie = rec.Result().Cookies()[0]
	if cookie.Name != "__Host-"+oidcFlowCookie || !cookie.Secure {
		t.Fatalf("secure flow cookie = %#v", cookie)
	}
}
