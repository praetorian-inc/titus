package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ruleBlock represents the line range of a single rule entry in a YAML file.
type ruleBlock struct {
	start int // line index (0-based) of "- name:" or "- id:"
	end   int // line index (inclusive) of last line of this rule
	id    string
}

var (
	// idLineRe matches "id: np.xxx" or "  id: np.xxx" with any leading whitespace.
	idLineRe = regexp.MustCompile(`^(\s*)id:\s*([a-zA-Z0-9._-]+)\s*$`)
	// baseScoreRe matches an existing "base_score: N" line.
	baseScoreRe = regexp.MustCompile(`^(\s*)base_score:\s*(\d+)\s*$`)
	// ruleStartRe matches the first line of a new rule: "- name:" or "- id:"
	ruleStartRe = regexp.MustCompile(`^(\s*)- (name|id):`)
)

// applyScoresToRules walks rulesDir, applies scores to matching rules, and
// returns (numChanged, missingRuleIDs, error). In dry-run mode (apply=false),
// no files are written but numChanged still reflects what would change.
func applyScoresToRules(rulesDir string, scores map[string]ScoreEntry, apply bool) (int, []string, error) {
	seen := map[string]bool{}
	totalChanged := 0

	err := filepath.WalkDir(rulesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yml" {
			return nil
		}
		changed, err := applyToFile(path, scores, seen, apply)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		totalChanged += changed
		return nil
	})
	if err != nil {
		return 0, nil, err
	}

	// Report rule IDs in scores that were never found in any YAML file.
	var missing []string
	for id := range scores {
		if !seen[id] {
			missing = append(missing, id)
		}
	}
	return totalChanged, missing, nil
}

// applyToFile reads a single YAML file, identifies rule blocks, and either
// inserts or updates base_score lines as needed. The seen map is updated with
// every rule ID encountered.
func applyToFile(path string, scores map[string]ScoreEntry, seen map[string]bool, apply bool) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	// Parse into lines so we can reassemble with modifications.
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}

	// Pass 1: identify rule blocks (start line = "- name:" or "- id:" with any indent)
	var blocks []ruleBlock
	var current *ruleBlock
	for i, line := range lines {
		if ruleStartRe.MatchString(line) {
			if current != nil {
				current.end = i - 1
				blocks = append(blocks, *current)
			}
			current = &ruleBlock{start: i, end: len(lines) - 1}
		}
		if current != nil && current.id == "" {
			if m := idLineRe.FindStringSubmatch(line); m != nil {
				current.id = m[2]
			}
		}
	}
	if current != nil {
		blocks = append(blocks, *current)
	}

	// Mark all rule IDs we encounter regardless of whether they're in scores.
	for _, b := range blocks {
		if b.id != "" {
			if _, inScores := scores[b.id]; inScores {
				seen[b.id] = true
			}
		}
	}

	// Pass 2: for each block with an id in scores, insert or update base_score.
	// Process blocks in reverse so line insertions don't shift indices.
	changed := 0
	for i := len(blocks) - 1; i >= 0; i-- {
		b := blocks[i]
		entry, ok := scores[b.id]
		if !ok {
			continue
		}

		// Look for existing base_score line within [b.start, b.end]
		existingIdx := -1
		var existingIndent string
		var existingValue int
		for j := b.start; j <= b.end; j++ {
			if m := baseScoreRe.FindStringSubmatch(lines[j]); m != nil {
				existingIdx = j
				existingIndent = m[1]
				existingValue, _ = strconv.Atoi(m[2])
				break
			}
		}

		if existingIdx >= 0 {
			if existingValue == entry.BaseScore {
				continue // already correct — idempotent no-op
			}
			// Update existing line in-place
			lines[existingIdx] = fmt.Sprintf("%sbase_score: %d", existingIndent, entry.BaseScore)
			changed++
			continue
		}

		// No existing base_score — find the id line within the block and insert after it.
		idLineIdx := -1
		var idIndent string
		for j := b.start; j <= b.end; j++ {
			if m := idLineRe.FindStringSubmatch(lines[j]); m != nil {
				idLineIdx = j
				idIndent = m[1]
				break
			}
		}
		if idLineIdx < 0 {
			// Should not happen — block was identified by having an id line.
			continue
		}

		newLine := fmt.Sprintf("%sbase_score: %d", idIndent, entry.BaseScore)
		newLines := make([]string, 0, len(lines)+1)
		newLines = append(newLines, lines[:idLineIdx+1]...)
		newLines = append(newLines, newLine)
		newLines = append(newLines, lines[idLineIdx+1:]...)
		lines = newLines

		// Update remaining block end indices to account for inserted line.
		for k := 0; k < i; k++ {
			if blocks[k].start > idLineIdx {
				blocks[k].start++
				blocks[k].end++
			} else if blocks[k].end >= idLineIdx {
				blocks[k].end++
			}
		}
		changed++
	}

	if changed > 0 && apply {
		// Reassemble and write, preserving trailing newline if original had one.
		output := strings.Join(lines, "\n")
		if bytes.HasSuffix(data, []byte("\n")) && !strings.HasSuffix(output, "\n") {
			output += "\n"
		}
		if err := os.WriteFile(path, []byte(output), 0644); err != nil {
			return 0, err
		}
	}
	return changed, nil
}
