package matcher

import (
	"runtime"
	"testing"
)

func BenchmarkSnippetMemoryRetention(b *testing.B) {
	const (
		numFiles   = 100
		fileSize   = 1 * 1024 * 1024 // 1MB per file
		matchStart = 500000
		matchLen   = 40
	)

	b.Run("SubSlice", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var retained [][]byte
			for f := 0; f < numFiles; f++ {
				content := make([]byte, fileSize)
				// Write some data at the match location
				copy(content[matchStart:], []byte("SECRET_KEY=AKIAIOSFODNN7EXAMPLE!"))
				// Old way: sub-slice pins entire 1MB
				snippet := content[matchStart : matchStart+matchLen]
				retained = append(retained, snippet)
			}
			runtime.GC()
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			b.ReportMetric(float64(ms.HeapInuse)/(1024*1024), "heap-MB")
			runtime.KeepAlive(retained)
		}
	})

	b.Run("Copy", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var retained [][]byte
			for f := 0; f < numFiles; f++ {
				content := make([]byte, fileSize)
				copy(content[matchStart:], []byte("SECRET_KEY=AKIAIOSFODNN7EXAMPLE!"))
				// New way: copy decouples from backing array
				snippet := append([]byte{}, content[matchStart:matchStart+matchLen]...)
				retained = append(retained, snippet)
			}
			runtime.GC()
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			b.ReportMetric(float64(ms.HeapInuse)/(1024*1024), "heap-MB")
			runtime.KeepAlive(retained)
		}
	})
}

func BenchmarkExtractContextAllocs(b *testing.B) {
	// Build a realistic content buffer with multiple lines
	content := make([]byte, 0, 10000)
	for i := 0; i < 200; i++ {
		content = append(content, []byte("this is line number something or other for testing\n")...)
	}
	start := 2500
	end := 2540

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		before, after := ExtractContext(content, start, end, 3)
		runtime.KeepAlive(before)
		runtime.KeepAlive(after)
	}
}
