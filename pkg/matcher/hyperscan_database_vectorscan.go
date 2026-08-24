//go:build !wasm && cgo && vectorscan

package matcher

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/flier/gohs/hyperscan"
	"github.com/praetorian-inc/titus/pkg/types"
)

func hyperscanPatterns(rules []*types.Rule) []*hyperscan.Pattern {
	patternInfo, _ := prepareHyperscanPatterns(rules)
	patterns := make([]*hyperscan.Pattern, len(patternInfo))
	for i, info := range patternInfo {
		patterns[i] = info.pattern
	}
	return patterns
}

func hyperscanDatabaseFilename(patterns []*hyperscan.Pattern) string {
	digest := sha256.New()
	var value [8]byte
	for _, pattern := range patterns {
		binary.BigEndian.PutUint64(value[:], uint64(pattern.Id))
		_, _ = digest.Write(value[:])
		binary.BigEndian.PutUint64(value[:], uint64(pattern.Flags))
		_, _ = digest.Write(value[:])
		binary.BigEndian.PutUint64(value[:], uint64(len(pattern.Expression)))
		_, _ = digest.Write(value[:])
		_, _ = digest.Write([]byte(pattern.Expression))
	}
	return hex.EncodeToString(digest.Sum(nil)) + ".hsdb"
}

func loadOrCompileHyperscanDatabase(patterns []*hyperscan.Pattern, warnf func(string, ...any)) (hyperscan.BlockDatabase, error) {
	var cachePath string
	if dir, err := RulesCacheDir(); err == nil {
		cachePath = filepath.Join(dir, hyperscanDatabaseFilename(patterns))
		data, err := os.ReadFile(cachePath)
		if err == nil {
			database, deserializeErr := hyperscan.UnmarshalBlockDatabase(data)
			if deserializeErr == nil {
				fmt.Fprintf(os.Stderr, "[vectorscan] loaded cached Hyperscan database %s\n", cachePath)
				return database, nil
			}
			warnHyperscanDatabase(warnf, "cannot deserialize Hyperscan database %s; compiling at runtime: %v", cachePath, deserializeErr)
		} else if !errors.Is(err, os.ErrNotExist) {
			warnHyperscanDatabase(warnf, "cannot read Hyperscan database %s; compiling at runtime: %v", cachePath, err)
		}
	} else {
		warnHyperscanDatabase(warnf, "cannot resolve Titus rules cache; compiling at runtime: %v", err)
	}

	database, err := hyperscan.NewBlockDatabase(patterns...)
	if err != nil {
		return nil, err
	}

	if cachePath != "" {
		if err := cacheHyperscanDatabase(cachePath, database); err != nil {
			warnHyperscanDatabase(warnf, "cannot cache Hyperscan database %s: %v", cachePath, err)
		} else {
			fmt.Fprintf(os.Stderr, "[vectorscan] cached Hyperscan database %s\n", cachePath)
		}
	}

	return database, nil
}

func cacheHyperscanDatabase(path string, database hyperscan.BlockDatabase) error {
	data, err := database.Marshal()
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}

	temporary, err := os.CreateTemp(dir, ".titus-rules-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary cache file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()

	if err := temporary.Chmod(0o640); err != nil {
		return fmt.Errorf("set cache permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close cache: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish cache: %w", err)
	}
	return nil
}

func warnHyperscanDatabase(warnf func(string, ...any), format string, args ...any) {
	if warnf != nil {
		warnf(format, args...)
		return
	}
	fmt.Fprintf(os.Stderr, "[vectorscan] warning: "+format+"\n", args...)
}
