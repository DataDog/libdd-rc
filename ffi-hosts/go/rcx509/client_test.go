package rcx509

import "testing"

func TestValidateURLAcceptsValidURLs(t *testing.T) {
	urls := []string{
		"ws://example.com",
		"wss://example.com",
		"wss://example.com:443/path",
	}

	for _, u := range urls {
		if err := validateURL(u); err != nil {
			t.Errorf("validateURL(%q) returned unexpected error: %v", u, err)
		}
	}
}

func TestValidateURLRejectsInvalidURLs(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "invalid scheme", url: "http://example.com"},
		{name: "missing host", url: "ws:///path"},
		{name: "malformed url", url: "://not-a-url"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateURL(tt.url); err == nil {
				t.Errorf("validateURL(%q) expected an error, got nil", tt.url)
			}
		})
	}
}
