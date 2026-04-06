package matcher

import (
	"unicode/utf8"

	"github.com/dlclark/regexp2"
	"github.com/praetorian-inc/titus/pkg/types"
)

// runeSpanToByteSpan converts a rune-based span to a byte-based span.
// regexp2 returns Match.Index and Match.Length as rune counts, not byte counts.
// See: https://github.com/dlclark/regexp2/blob/master/match.go (Capture struct documentation)
func runeSpanToByteSpan(content []byte, runeStart, runeLength int) (byteStart, byteEnd int) {
	runeEnd := runeStart + runeLength
	byteStart = len(content)
	byteEnd = len(content)

	runeIdx := 0
	byteIdx := 0
	for byteIdx < len(content) {
		if runeIdx == runeStart {
			byteStart = byteIdx
		}
		if runeIdx == runeEnd {
			byteEnd = byteIdx
			return
		}
		_, size := utf8.DecodeRune(content[byteIdx:])
		byteIdx += size
		runeIdx++
	}
	// If runeEnd lands exactly at the end of content
	if runeIdx == runeEnd {
		byteEnd = byteIdx
	}
	return
}

// extractCaptureGroups extracts positional capture groups from a regexp2 match.
func extractCaptureGroups(match *regexp2.Match) [][]byte {
	var groups [][]byte
	matchGroups := match.Groups()
	for i := 1; i < len(matchGroups); i++ {
		group := matchGroups[i]
		if len(group.Captures) > 0 {
			capture := group.Captures[0]
			groups = append(groups, []byte(capture.String()))
		}
	}
	return groups
}

// extractNamedGroups extracts named capture groups from a regexp2 match.
func extractNamedGroups(match *regexp2.Match, groupNames []string) map[string][]byte {
	namedGroups := make(map[string][]byte)
	for _, name := range groupNames {
		// Skip numbered groups (they show up as "0", "1", etc.)
		if name == "" || (len(name) > 0 && name[0] >= '0' && name[0] <= '9') {
			continue
		}
		group := match.GroupByName(name)
		if group != nil && len(group.Captures) > 0 {
			namedGroups[name] = []byte(group.Captures[0].String())
		}
	}
	return namedGroups
}

// buildMatchResult constructs a types.Match from match data.
// runeStart and runeLength come from regexp2.Match.Index and Match.Length (rune-based).
// matchedText should be obtained from regexp2.Match.String().
func buildMatchResult(
	blobID types.BlobID,
	rule *types.Rule,
	runeStart int,
	runeLength int,
	matchedText []byte,
	groups [][]byte,
	namedGroups map[string][]byte,
	content []byte,
	contextLines int,
) *types.Match {
	// Convert rune-based span to byte-based span
	start, end := runeSpanToByteSpan(content, runeStart, runeLength)

	var before, after []byte
	if contextLines > 0 {
		before, after = ExtractContext(content, start, end, contextLines)
	}

	result := &types.Match{
		BlobID:   blobID,
		RuleID:   rule.ID,
		RuleName: rule.Name,
		Location: types.Location{
			Offset: types.OffsetSpan{
				Start: int64(start),
				End:   int64(end),
			},
		},
		Groups:      groups,
		NamedGroups: namedGroups,
		Snippet: types.Snippet{
			Before:   before,
			Matching: matchedText,
			After:    after,
		},
	}

	// Compute structural ID for deduplication
	result.StructuralID = result.ComputeStructuralID(rule.StructuralID)

	// Compute finding ID for content-based deduplication (NoseyParker-compatible)
	result.FindingID = types.ComputeFindingID(rule.StructuralID, groups)

	return result
}
