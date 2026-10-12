package api

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

func TestProxyTestFetchRejectsPrivateDestinationBeforeRequest(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "::1", "fc00::1"} {
		t.Run(ip, func(t *testing.T) {
			lookup := func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
			}
			var requests atomic.Int32
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests.Add(1)
				return nil, context.Canceled
			})}
			server := newTestServerWithResolver(t, "secret", t.TempDir(), lookup)
			server.httpClient = client
			allowTestFetchVendor(t, server)
			rec := performSecurityTestFetch(server)
			var body struct {
				Allowed bool   `json:"allowed"`
				Reason  string `json:"reason"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusOK || body.Allowed || body.Reason == "" {
				t.Fatalf("expected target rejection, got %d %s", rec.Code, rec.Body.String())
			}
			if requests.Load() != 0 {
				t.Fatal("private destination reached the HTTP transport")
			}
		})
	}
}

func TestProxyTestFetchBlocksDNSRebindingAtConnection(t *testing.T) {
	var lookups atomic.Int32
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		ip := "93.184.216.34"
		if lookups.Add(1) > 1 {
			ip = "127.0.0.1"
		}
		return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
	}
	server := newTestServerWithResolver(t, "secret", t.TempDir(), lookup)
	// Keep the production transport and safe dialer; record its rejection.
	client := proxy.DefaultHTTPClientWithResolver(lookup)
	client.Timeout = 2 * time.Second
	transport := client.Transport.(*http.Transport)
	t.Cleanup(transport.CloseIdleConnections)
	safeDial := transport.DialContext
	var blocked atomic.Bool
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := safeDial(ctx, network, address)
		blocked.Store(proxy.SafetyReason(err) == proxy.SafetyReasonLoopbackIP)
		return conn, err
	}
	server.httpClient = client
	allowTestFetchVendor(t, server)
	rec := performSecurityTestFetch(server)
	if rec.Code != http.StatusBadGateway || lookups.Load() != 2 || !blocked.Load() {
		t.Fatalf("expected connection-time rebinding rejection: status=%d lookups=%d blocked=%v body=%s", rec.Code, lookups.Load(), blocked.Load(), rec.Body.String())
	}
}

func TestProxyTestFetchDoesNotFollowPrivateRedirect(t *testing.T) {
	var requests atomic.Int32
	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			requests.Add(1)
			if r.URL.String() != "https://www.jstor.org/" {
				t.Errorf("unexpected outbound request: %s", r.URL)
			}
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": {"https://127.0.0.1/private"}},
				Body:       io.NopCloser(strings.NewReader("redirect response")),
				Request:    r,
			}, nil
		}),
		// Deliberately permissive: the endpoint must override this policy.
		CheckRedirect: func(*http.Request, []*http.Request) error { return nil },
	}
	server := newTestServerWithResolver(t, "secret", t.TempDir(), publicTestResolver)
	server.httpClient = client
	allowTestFetchVendor(t, server)
	rec := performSecurityTestFetch(server)
	var body struct {
		Allowed bool `json:"allowed"`
		Status  int  `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || !body.Allowed || body.Status != http.StatusFound || requests.Load() != 1 {
		t.Fatalf("expected one request returning the redirect: requests=%d response=%d %s", requests.Load(), rec.Code, rec.Body.String())
	}
}

func allowTestFetchVendor(t *testing.T, server *Server) {
	t.Helper()
	if err := server.store.UpsertResource(resources.Resource{
		ID: "jstor", Name: "JSTOR", Status: "active",
		Domains: []resources.DomainRule{{Host: "www.jstor.org", Match: "exact"}},
	}); err != nil {
		t.Fatal(err)
	}
}

func performSecurityTestFetch(server *Server) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/proxy/test-fetch", strings.NewReader(`{"url":"https://www.jstor.org/"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	return rec
}
