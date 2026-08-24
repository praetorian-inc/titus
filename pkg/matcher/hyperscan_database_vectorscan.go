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

// HyperscanDatabaseFilename returns the filename for the ordered Hyperscan
// patterns produced by rules. The file itself is the unmodified byte stream
// returned by hs_serialize_database.
func HyperscanDatabaseFilename(rules []*types.Rule) (string, error) {
	patterns := hyperscanPatterns(rules)
	if len(patterns) == 0 {
		return "", errors.New("no Hyperscan-compatible rules provided")
	}
	return hyperscanDatabaseFilename(patterns), nil
}

// CompileHyperscanDatabase compiles rules for a generic CPU and returns the
// raw byte stream produced by hs_serialize_database.
func CompileHyperscanDatabase(rules []*types.Rule) ([]byte, error) {
	patterns := hyperscanPatterns(rules)
	if len(patterns) == 0 {
		return nil, errors.New("no Hyperscan-compatible rules provided")
	}

	database, err := hyperscan.Patterns(patterns).ForPlatform(
		hyperscan.BlockMode,
		hyperscan.NewPlatform(hyperscan.Generic, 0),
	)
	if err != nil {
		return nil, fmt.Errorf("compile Hyperscan database: %w", err)
	}
	defer database.Close()

	data, err := database.Marshal()
	if err != nil {
		return nil, fmt.Errorf("serialize Hyperscan database: %w", err)
	}
	return data, nil
}

// WriteHyperscanDatabase writes a raw serialized database to dir.
func WriteHyperscanDatabase(dir string, rules []*types.Rule) (string, error) {
	filename, err := HyperscanDatabaseFilename(rules)
	if err != nil {
		return "", err
	}
	data, err := CompileHyperscanDatabase(rules)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create Hyperscan database directory: %w", err)
	}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return "", fmt.Errorf("write Hyperscan database: %w", err)
	}
	return path, nil
}

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
	if dir, err := RulesCacheDir(); err == nil {
		path := filepath.Join(dir, hyperscanDatabaseFilename(patterns))
		data, err := os.ReadFile(path)
		if err == nil {
			database, deserializeErr := hyperscan.UnmarshalBlockDatabase(data)
			if deserializeErr == nil {
				fmt.Fprintf(os.Stderr, "[vectorscan] loaded serialized Hyperscan database %s\n", path)
				return database, nil
			}
			warnHyperscanDatabase(warnf, "cannot deserialize Hyperscan database %s; compiling at runtime: %v", path, deserializeErr)
		} else if !errors.Is(err, os.ErrNotExist) {
			warnHyperscanDatabase(warnf, "cannot read Hyperscan database %s; compiling at runtime: %v", path, err)
		}
	} else {
		warnHyperscanDatabase(warnf, "cannot resolve Titus rules cache; compiling at runtime: %v", err)
	}

	return hyperscan.NewBlockDatabase(patterns...)
}

func warnHyperscanDatabase(warnf func(string, ...any), format string, args ...any) {
	if warnf != nil {
		warnf(format, args...)
		return
	}
	fmt.Fprintf(os.Stderr, "[vectorscan] warning: "+format+"\n", args...)
}
