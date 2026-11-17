package rcx509

import (
	"slices"
	"testing"
)

func TestNormalizeTags(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "nil", in: nil, want: []string{}},
		{name: "sorted", in: []string{"env:prod", "app:web"}, want: []string{"app:web", "env:prod"}},
		{name: "trimmed", in: []string{" env:prod ", "\tapp:web\n"}, want: []string{"app:web", "env:prod"}},
		{name: "empty dropped", in: []string{"", "  ", "env:prod"}, want: []string{"env:prod"}},
		{name: "deduplicated", in: []string{"env:prod", "env:prod", " env:prod"}, want: []string{"env:prod"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeTags(tt.in); !slices.Equal(got, tt.want) {
				t.Errorf("normalizeTags(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestSetHostTagsBeforeStart confirms tags can be set before Start, and reach
// the FFI layer normalized.
func TestSetHostTagsBeforeStart(t *testing.T) {
	ffi := &fakeFFIContext{}
	client := &Client{ffiCtx: ffi}

	if err := client.SetHostTags([]string{"env:prod", " host:a ", "env:prod"}); err != nil {
		t.Fatalf("SetHostTags() returned unexpected error: %v", err)
	}

	want := [][]string{{"env:prod", "host:a"}}
	if !slices.EqualFunc(ffi.hostTagsCalls, want, slices.Equal) {
		t.Fatalf("FFI SetHostTags calls = %q, want %q", ffi.hostTagsCalls, want)
	}
}

// TestSetHostTagsOnlyPassesChanges confirms a set equal to the last one, after
// normalization, does not reach the FFI layer again, while a changed set does.
func TestSetHostTagsOnlyPassesChanges(t *testing.T) {
	ffi := &fakeFFIContext{}
	client := &Client{ffiCtx: ffi}

	for _, tags := range [][]string{
		{"env:prod", "host:a"},
		{"host:a", "env:prod"}, // same set, different order
		{"env:prod", "host:b"},
	} {
		if err := client.SetHostTags(tags); err != nil {
			t.Fatalf("SetHostTags(%q) returned unexpected error: %v", tags, err)
		}
	}

	want := [][]string{{"env:prod", "host:a"}, {"env:prod", "host:b"}}
	if !slices.EqualFunc(ffi.hostTagsCalls, want, slices.Equal) {
		t.Fatalf("FFI SetHostTags calls = %q, want %q", ffi.hostTagsCalls, want)
	}
}
