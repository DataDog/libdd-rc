package rcx509

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func dialHeaders(t *testing.T, apiKey string, httpClient *http.Client) http.Header {
	t.Helper()

	got := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		c.CloseNow()
	}))
	defer srv.Close()

	d := &CoderWebsocketDialer{APIKey: apiKey, HTTPClient: httpClient}
	conn, err := d.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), 5*time.Second)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	conn.CloseNow()

	return <-got
}

func TestDialerSendsAPIKeyHeader(t *testing.T) {
	if got := dialHeaders(t, "secret", nil).Get("DD-API-KEY"); got != "secret" {
		t.Fatalf("DD-API-KEY = %q, want %q", got, "secret")
	}
}

func TestDialerOmitsAPIKeyHeaderWhenUnset(t *testing.T) {
	if _, ok := dialHeaders(t, "", nil)["Dd-Api-Key"]; ok {
		t.Fatal("DD-API-KEY header sent with empty API key")
	}
}

func TestDialerUsesHTTPClientWithAPIKey(t *testing.T) {
	got := make(chan http.Header, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		c.CloseNow()
	}))
	defer srv.Close()

	d := &CoderWebsocketDialer{APIKey: "secret", HTTPClient: srv.Client()}
	conn, err := d.Dial(context.Background(), "wss"+strings.TrimPrefix(srv.URL, "https"), 5*time.Second)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	conn.CloseNow()

	if value := (<-got).Get(apiKeyHeader); value != "secret" {
		t.Fatalf("%s = %q, want %q", apiKeyHeader, value, "secret")
	}
}
