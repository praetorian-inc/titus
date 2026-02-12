//go:build !vectorscan

package matcher

// VectorscanAvailable returns whether vectorscan is available.
// This stub returns false when built without the vectorscan tag.
func VectorscanAvailable() bool {
	return false
}

// VectorscanInfo returns information about the Hyperscan build.
// This stub indicates vectorscan is not available.
func VectorscanInfo() string {
	return "vectorscan not available (build without vectorscan tag)"
}
