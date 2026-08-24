//go:build wasm || !cgo || !vectorscan

package matcher

import "github.com/praetorian-inc/titus/pkg/types"

// HyperscanDatabaseFilename is unavailable without the native matcher.
func HyperscanDatabaseFilename(_ []*types.Rule) (string, error) {
	return "", ErrHyperscanDatabaseUnavailable
}

// CompileHyperscanDatabase is unavailable without the native matcher.
func CompileHyperscanDatabase(_ []*types.Rule) ([]byte, error) {
	return nil, ErrHyperscanDatabaseUnavailable
}

// WriteHyperscanDatabase is unavailable without the native matcher.
func WriteHyperscanDatabase(_ string, _ []*types.Rule) (string, error) {
	return "", ErrHyperscanDatabaseUnavailable
}
