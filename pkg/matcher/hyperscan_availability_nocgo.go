//go:build !wasm && (!cgo || !hyperscan)

package matcher

// hyperscanAvailable returns false when Hyperscan is not available (non-CGO build or missing hyperscan tag).
func hyperscanAvailable() bool {
	return false
}
