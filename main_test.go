package main

import (
	"testing"
)

func TestDerivePort(t *testing.T) {
	tests := []struct {
		listen   string
		wantPort string
	}{
		{":8080", "8080"},
		{"0.0.0.0:9090", "9090"},
		{"127.0.0.1:80", "80"},
		{"[::1]:443", "443"},
	}

	for _, tt := range tests {
		t.Run(tt.listen, func(t *testing.T) {
			got := derivePort(tt.listen)
			if got != tt.wantPort {
				t.Errorf("derivePort(%q) = %q, want %q", tt.listen, got, tt.wantPort)
			}
		})
	}
}

func TestDerivePort_Invalid(t *testing.T) {
	// Invalid format falls back to "80" with a warning log.
	got := derivePort("invalid")
	if got != "80" {
		t.Errorf("derivePort(\"invalid\") = %q, want \"80\"", got)
	}
}
