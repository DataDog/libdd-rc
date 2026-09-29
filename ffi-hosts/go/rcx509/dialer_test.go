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

func dialHeaders(t *testing.T, apiKey string) http.Header {
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

	d := &CoderWebsocketDialer{APIKey: apiKey}
	conn, err := d.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), 5*time.Second)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	conn.CloseNow()

	return <-got
}

func TestDialerSendsAPIKeyHeader(t *testing.T) {
	if got := dialHeaders(t, "secret").Get("DD-API-KEY"); got != "secret" {
		t.Fatalf("DD-API-KEY = %q, want %q", got, "secret")
	}
}

func TestDialerOmitsAPIKeyHeaderWhenUnset(t *testing.T) {
	if _, ok := dialHeaders(t, "")["Dd-Api-Key"]; ok {
		t.Fatal("DD-API-KEY header sent with empty API key")
	}
}
