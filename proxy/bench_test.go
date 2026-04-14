package proxy

import (
	"testing"
)

func BenchmarkBuildEnvKey(b *testing.B) {
	key := []byte("X-Custom-Header")
	var buf [256]byte

	b.ReportAllocs()
	for b.Loop() {
		buildEnvKey(buf[:0], key)
	}
}

func BenchmarkIsBlockedHeader(b *testing.B) {
	key := []byte("X-Forwarded-For")
	b.ReportAllocs()
	for b.Loop() {
		isBlockedHeader(key)
	}
}

func BenchmarkIsBlockedHeader_NotBlocked(b *testing.B) {
	key := []byte("X-Custom")
	b.ReportAllocs()
	for b.Loop() {
		isBlockedHeader(key)
	}
}
