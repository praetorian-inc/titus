package enum

import (
	"cmp"
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/praetorian-inc/titus/pkg/repoid"
	"github.com/praetorian-inc/titus/pkg/types"
)

// RepoInfo holds basic repository information for clone-based scanning.
type RepoInfo struct {
	Name          string // Full name (e.g., "kubernetes/kubernetes")
	CloneURL      string // HTTPS clone URL
	DefaultBranch string
}

// CloneEnumerator clones repositories and scans them.
// By default it does a full clone and filesystem scan.
// Set Git=true to do a full clone with git history scanning.
type CloneEnumerator struct {
	repos  []RepoInfo
	config Config
	Git    bool          // false = full clone + filesystem scan, true = full clone + git history (thorough)
	Depth  int           // override clone depth (0 = automatic: full clone for filesystem mode, unlimited for git mode)
	Delay  time.Duration // minimum delay between clones (from --rate-limit)
	Jitter time.Duration // maximum delay between clones (from --jitter); actual delay is random(Delay, Jitter)
	Token  string        // API token for authenticated cloning (passed via ephemeral credential helper)
}

// NewCloneEnumerator creates a new clone-based enumerator.
func NewCloneEnumerator(repos []RepoInfo, config Config) *CloneEnumerator {
	return &CloneEnumerator{repos: repos, config: config}
}

// stealthDelay returns the delay to wait before the next operation.
// If Jitter is set, returns a random duration between Delay and Jitter.
// If only Delay is set, returns Delay (fixed).
// If neither is set, returns 0.
func (e *CloneEnumerator) stealthDelay() time.Duration {
	if e.Jitter > 0 {
		minDelay := e.Delay
		maxDelay := e.Jitter
		if maxDelay <= minDelay {
			return minDelay
		}
		rangeNs := (maxDelay - minDelay).Nanoseconds()
		if rangeNs <= 0 {
			return minDelay
		}
		n, err := rand.Int(rand.Reader, big.NewInt(rangeNs))
		if err != nil {
			return minDelay
		}
		randomNs := n.Int64()
		return minDelay + time.Duration(randomNs)
	}
	return e.Delay
}

// EstimateScanTime returns the estimated total scan time based on delay/jitter settings.
// It calculates the average delay per repo multiplied by the number of repos.
func (e *CloneEnumerator) EstimateScanTime() time.Duration {
	if len(e.repos) == 0 {
		return 0
	}
	var avgDelay time.Duration
	if e.Jitter > 0 {
		// Average of uniform distribution between Delay and Jitter
		avgDelay = (e.Delay + e.Jitter) / 2
	} else {
		avgDelay = e.Delay
	}
	// n-1 delays (no delay before the first repo)
	return avgDelay * time.Duration(len(e.repos)-1)
}

// Enumerate clones each repository, scans it, and cleans up.
func (e *CloneEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	for i, repo := range e.repos {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Stealth/rate-limit: delay between repos (skip before first)
		if (e.Delay > 0 || e.Jitter > 0) && i > 0 {
			wait := e.stealthDelay()
			if wait > 0 {
				fmt.Fprintf(os.Stderr, "Waiting %s before next repo (%d/%d)...\n", wait.Round(time.Second), i+1, len(e.repos))
				select {
				case <-time.After(wait):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}

		if err := e.cloneAndScan(ctx, repo, callback); err != nil {
			// Log error and continue to next repo. Never print CloneURL: it
			// may carry a token.
			id, _ := cloneIdentity(repo)
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", id, err)
			continue
		}
	}
	return nil
}

// cloneIdentity returns the repository value for a clone: the normalized
// CloneURL when it is a network remote (credentials, port and ".git"
// stripped), otherwise the listed name as typed. No host is guessed (SEC-3).
func cloneIdentity(repo RepoInfo) (id string, remote bool) {
	if id, ok := repoid.Normalize(repo.CloneURL); ok {
		return id, true
	}
	return typedRepoIdentity(cmp.Or(repo.Name, repo.CloneURL)), false
}

func (e *CloneEnumerator) cloneAndScan(ctx context.Context, repo RepoInfo, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	id, remote := cloneIdentity(repo)

	tmpDir, err := os.MkdirTemp("", "titus-clone-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	clonePath := filepath.Join(tmpDir, "repo")

	// Determine effective clone depth
	depth := e.Depth

	// Build clone args
	cloneArgs := []string{"-c", "http.postBuffer=524288000"}

	// Inject ephemeral credential helper when a token is provided.
	// This avoids embedding the token in the URL (server logs) or command line (ps).
	// The helper reads the token from TITUS_CLONE_TOKEN env var at runtime.
	if e.Token != "" {
		cloneArgs = append(cloneArgs,
			"-c", `credential.helper=`,
			"-c", `credential.helper=!f() { echo username=titus; echo password="$TITUS_CLONE_TOKEN"; }; f`,
		)
	}

	cloneArgs = append(cloneArgs, "clone", "--quiet")
	if e.Git && depth == 0 {
		// Full history: bare clone for efficiency (no working tree needed)
		cloneArgs = append(cloneArgs, "--bare")
	}
	if depth > 0 {
		cloneArgs = append(cloneArgs, "--depth", strconv.Itoa(depth))
	}
	cloneArgs = append(cloneArgs, repo.CloneURL, clonePath)

	fmt.Fprintf(os.Stderr, "Cloning %s...\n", id)
	cmd := exec.CommandContext(ctx, "git", cloneArgs...)
	cmd.Stderr = os.Stderr

	if e.Token != "" {
		// Isolate from user's git config to prevent credential helper conflicts,
		// and pass the token via environment variable (not visible in ps).
		cmd.Env = append(os.Environ(),
			"TITUS_CLONE_TOKEN="+e.Token,
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_TERMINAL_PROMPT=0",
		)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cloning %s: %w", id, err)
	}

	cloneConfig := e.config
	cloneConfig.Root = clonePath

	if e.Git {
		// Git history mode: walk all commits. The native enumerator already
		// reports every location of each blob; only the identity changes.
		// RepoRoot is cleared because the temp clone is deleted.
		gitEnum := NewGitEnumerator(cloneConfig)
		if depth == 0 {
			gitEnum.WalkAll = true
		}
		return gitEnum.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
			if gp, ok := prov.(types.GitProvenance); ok {
				gp.RepoPath, gp.RemoteIdentity, gp.RepoRoot = id, remote, ""
				return callback(content, blobID, gp)
			}
			return callback(content, blobID, prov)
		})
	}

	// Filesystem mode (default): fast scan of the working tree. Commit
	// metadata comes from the blob index, best effort: on error the index is
	// nil, which every lookup treats as empty.
	idx, _ := buildBlobIndex(ctx, clonePath)
	idx.writeWarnings(os.Stderr)

	return NewFilesystemEnumerator(cloneConfig).Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		fp, ok := prov.(types.FileProvenance)
		if !ok {
			return callback(content, blobID, prov)
		}
		rel, err := filepath.Rel(clonePath, fp.FilePath)
		if err != nil {
			rel = fp.FilePath
		}
		rel = filepath.ToSlash(rel)
		commit, truncated := committedAt(idx, blobID, fp.FilePath, rel)
		loc := types.GitLocation{Path: rel, Commit: commit}
		return callback(content, blobID, types.GitProvenance{
			RepoPath:           id,
			BlobPath:           rel,
			Commit:             loc.Commit,
			RemoteIdentity:     remote,
			Locations:          []types.GitLocation{loc},
			LocationsTruncated: truncated,
		})
	})
}

// committedAt returns the commit recorded in idx for the blob at rel, and
// whether the index dropped a location of that blob at its size limit (R1),
// in which case the commit may be missing or not the earliest. The scanned
// content may be a decoded form of the file (UTF-16), so when the index has
// no entry for blobID at all the raw file is hashed and looked up again, and
// the mark is that of whichever id the index knows the file by. When it has
// entries but none at rel (a truncated index, or a path not yet committed)
// the content is taken as the raw file and not re-read; a decoded file whose
// text is also committed elsewhere as UTF-8 is the one case that then goes
// without commit metadata.
func committedAt(idx *blobIndex, blobID types.BlobID, file, rel string) (*types.CommitMetadata, bool) {
	if idx == nil {
		return nil, false
	}
	truncated := idx.locationsTruncated(blobID)
	if locs := idx.lookup(blobID); len(locs) > 0 {
		return commitForPath(locs, rel), truncated
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, truncated
	}
	if rawID := types.ComputeBlobID(raw); rawID != blobID {
		return commitForPath(idx.lookup(rawID), rel), truncated || idx.locationsTruncated(rawID)
	}
	return nil, truncated
}

func commitForPath(locs []types.GitLocation, rel string) *types.CommitMetadata {
	for _, l := range locs {
		if l.Path == rel {
			return l.Commit
		}
	}
	return nil
}
