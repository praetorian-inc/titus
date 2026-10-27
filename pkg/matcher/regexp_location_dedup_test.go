//go:build !wasm

package matcher

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ENG-9178: no secret may fall through. PortableRegexpMatcher must report every
// location of every secret, in every blob, whatever else is scanned beside it.

const sharedSecret = "AKIAZ52KNG5GARBXTEST"

func awsKeyRule() *types.Rule {
	return &types.Rule{
		ID:           "eng9178.aws",
		Name:         "AWS Access Key",
		Pattern:      `(AKIA[0-9A-Z]{16})`,
		StructuralID: "eng9178-aws-structural-id",
	}
}

// padTo appends filler lines until content is at least size bytes.
func padTo(content string, size int) string {
	var b strings.Builder
	b.WriteString(content)
	for b.Len() < size {
		b.WriteString("filler line with nothing interesting in it\n")
	}
	return b.String()
}

// pathSizes covers both MatchWithBlobID paths: sequential (< parallelThreshold)
// and rule-parallel (>= parallelThreshold).
var pathSizes = []struct {
	name    string
	minSize int
}{
	{"sequential", 0},
	{"parallel", parallelThreshold + 1},
}

func requireParallelPath(t *testing.T, minSize int, content []byte) {
	t.Helper()
	if minSize > 0 {
		require.GreaterOrEqual(t, len(content), parallelThreshold, "fixture must take the parallel path")
	} else {
		require.Less(t, len(content), parallelThreshold, "fixture must take the sequential path")
	}
}

// TestPortableRegexp_ConcurrentBlobsSharingSecret: one matcher, many goroutines,
// distinct blobs that all hold the same secret. Each blob is its own finding
// location and must get its own match; a matcher-wide content-keyed dedup drops
// all but the first blob to report the secret.
func TestPortableRegexp_ConcurrentBlobsSharingSecret(t *testing.T) {
	const (
		goroutines = 64
		rounds     = 5
	)

	for _, size := range pathSizes {
		t.Run(size.name, func(t *testing.T) {
			matcher, err := NewPortableRegexp([]*types.Rule{awsKeyRule()}, 0, nil)
			require.NoError(t, err)

			blobs := make([][]byte, goroutines)
			for i := range goroutines {
				// Distinct prefix per blob gives a distinct BlobID; the secret is identical.
				blobs[i] = []byte(padTo(fmt.Sprintf("# blob %d\naws_access_key_id = %s\n", i, sharedSecret), size.minSize))
			}
			requireParallelPath(t, size.minSize, blobs[0])

			for round := range rounds {
				counts := make([]int, goroutines)
				blobIDs := make([]types.BlobID, goroutines)
				errs := make([]error, goroutines)

				var start, wg sync.WaitGroup
				start.Add(1)
				for i := range goroutines {
					wg.Add(1)
					go func() {
						defer wg.Done()
						start.Wait() // release all goroutines together to maximise overlap
						blobID := types.ComputeBlobID(blobs[i])
						matches, err := matcher.MatchWithBlobID(blobs[i], blobID)
						errs[i] = err
						counts[i] = len(matches)
						if len(matches) == 1 {
							blobIDs[i] = matches[0].BlobID
						}
					}()
				}
				start.Done()
				wg.Wait()

				var missed []int
				for i := range goroutines {
					require.NoError(t, errs[i], "round %d blob %d", round, i)
					if counts[i] != 1 {
						missed = append(missed, i)
					}
				}
				require.Empty(t, missed, "round %d: blobs whose secret was not reported exactly once (counts=%v)", round, counts)
				for i := range goroutines {
					assert.Equal(t, types.ComputeBlobID(blobs[i]), blobIDs[i], "round %d blob %d: match attributed to the wrong blob", round, i)
				}
			}
		})
	}
}

// TestPortableRegexp_EveryLocationInBlob: within one blob, a secret repeated on
// two lines is two findings, and a rule with no capture groups matching two
// different values is two findings. No location may be reported twice.
func TestPortableRegexp_EveryLocationInBlob(t *testing.T) {
	groupless := &types.Rule{
		ID:           "eng9178.groupless",
		Name:         "Groupless token",
		Pattern:      `tok_[a-z0-9]{12}`,
		StructuralID: "eng9178-groupless-structural-id",
	}

	cases := []struct {
		name      string
		rule      *types.Rule
		body      string
		wantMatch []string
	}{
		{
			name:      "same secret on two lines",
			rule:      awsKeyRule(),
			body:      "key1 = " + sharedSecret + "\nkey2 = " + sharedSecret + "\n",
			wantMatch: []string{sharedSecret, sharedSecret},
		},
		{
			name:      "group-less rule, two distinct values",
			rule:      groupless,
			body:      "a = tok_aaaaaaaaaaaa\nb = tok_bbbbbbbbbbbb\n",
			wantMatch: []string{"tok_aaaaaaaaaaaa", "tok_bbbbbbbbbbbb"},
		},
	}

	for _, tc := range cases {
		for _, size := range pathSizes {
			t.Run(tc.name+"/"+size.name, func(t *testing.T) {
				matcher, err := NewPortableRegexp([]*types.Rule{tc.rule}, 0, nil)
				require.NoError(t, err)

				content := []byte(padTo(tc.body, size.minSize))
				requireParallelPath(t, size.minSize, content)

				matches, err := matcher.MatchWithBlobID(content, types.ComputeBlobID(content))
				require.NoError(t, err)

				var got []string
				offsets := make(map[types.OffsetSpan]int)
				for _, m := range matches {
					got = append(got, string(content[m.Location.Offset.Start:m.Location.Offset.End]))
					offsets[m.Location.Offset]++
				}
				assert.ElementsMatch(t, tc.wantMatch, got, "every location must be reported")
				for span, n := range offsets {
					assert.Equal(t, 1, n, "location %v reported %d times", span, n)
				}
				assert.Len(t, offsets, len(tc.wantMatch), "each match must have a distinct location")
			})
		}
	}
}
