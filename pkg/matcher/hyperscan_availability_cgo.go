//go:build !wasm && cgo && hyperscan

package matcher

// hyperscanAvailable returns true when Hyperscan is available (CGO build with hyperscan tag).
func hyperscanAvailable() bool {
	return true
}
