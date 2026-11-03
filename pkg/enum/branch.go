package enum

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os/exec"
	"slices"
	"strings"
	"sync"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// Bounds on the branch resolver. Over a bound, the part it limits is left
// unresolved: a branch is omitted, never guessed.
const (
	defaultMaxHeadCommits    = 2_000_000              // commits reachable from HEAD
	defaultMaxBranches       = 1000                   // distinct branch short names
	defaultMaxBranchRefs     = 4 * defaultMaxBranches // refs under refs/heads and refs/remotes
	defaultMaxOffHeadCommits = 2_000_000              // commits off HEAD that a branch holds
	// Lines streamed by every off-HEAD walk together. A commit several
	// branches hold is streamed once per branch, so the distinct-commit bound
	// alone does not bound the work.
	defaultMaxOffHeadWalkLines = 4 * defaultMaxOffHeadCommits
	branchIDLineMax            = 256 // a commit id line is at most 65 bytes
	refsHeadsPrefix            = "refs/heads/"
	refsRemotesPrefix          = "refs/remotes/"
	branchRevListStderrLimit   = 4 << 10
	branchNoteHistoryTooLarge  = "titus: branch not recorded: history exceeds %d commits"
	branchNoteHeadUnreadable   = "titus: branch not recorded: could not read HEAD's history"
	branchNoteHeadCheckFailed  = "titus: branch not recorded: could not check whether HEAD names a commit"
	offHeadNotePrefix          = "titus: branch not recorded for commits outside the checked-out branch: "
)

// Tests lower these to reach a cap without a huge repository.
var (
	maxHeadCommits    = defaultMaxHeadCommits
	maxBranches       = defaultMaxBranches
	maxBranchRefs     = defaultMaxBranchRefs
	maxOffHeadCommits = defaultMaxOffHeadCommits

	maxOffHeadWalkLines = defaultMaxOffHeadWalkLines
)

// errBranchCap stops a walk that reached a bound.
var errBranchCap = errors.New("branch resolver bound reached")

// errBranchWalkCap and errBranchRefCap are errBranchCap for one bound each,
// so the warning can name the bound that was reached.
var (
	errBranchWalkCap = fmt.Errorf("off-HEAD walk lines: %w", errBranchCap)
	errBranchRefCap  = fmt.Errorf("branch refs: %w", errBranchCap)
)

// branchHit records which branch holds a commit that HEAD does not, and how
// many distinct branches do.
type branchHit struct {
	branch uint16 // index into branchResolver.names
	n      uint16 // distinct branches holding the commit, saturating
}

// branchResolver answers which branch contains a commit: the checked-out
// branch when it does, else the only branch that does, else "". It is built
// once, then read-only apart from the off-HEAD part, which fills in on first
// use under a sync.Once, so concurrent lookups are safe; a nil resolver
// resolves nothing.
type branchResolver struct {
	head    string     // checked-out branch short name; "" when detached or not on refs/heads
	headIDs [][32]byte // sorted ids reachable from HEAD; only when head != ""
	names   []string   // distinct branch short names; branchHit.branch indexes it
	off     map[[32]byte]branchHit
	offOK   bool      // off is complete; false leaves every commit outside HEAD unresolved
	notes   []string  // one warning per bound reached; guarded by mu
	warn    io.Writer // where a note added after writeWarnings goes; guarded by mu
	mu      sync.Mutex

	// lazyOff fills off, offOK and notes. It runs once, on the first lookup
	// of a commit HEAD does not hold, so a scan whose commits are all on HEAD
	// never walks the other branches.
	lazyOff func(ctx context.Context)
	offOnce sync.Once
	ctx     context.Context // lazyOff's context; see bindContext
}

// bindContext sets the context the off-HEAD walk runs under. The index is
// built under a context that ends with the build, but the walk runs during
// the scan, so the caller binds the scan's own. It must run before lookups.
func (r *branchResolver) bindContext(ctx context.Context) {
	if r != nil {
		r.ctx = ctx
	}
}

// addNote records a warning. Once writeWarnings has been given a writer, the
// off-HEAD walk runs after that call, so its notes go straight to it.
func (r *branchResolver) addNote(note string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notes = append(r.notes, note)
	if r.warn != nil {
		_, _ = fmt.Fprintln(r.warn, note)
	}
}

// of returns the branch that contains commitID, or "" when none or several
// do or none could be established.
func (r *branchResolver) of(commitID string) string {
	if r == nil {
		return ""
	}
	id, ok := parseCommitKey(commitID)
	if !ok {
		return ""
	}
	if r.head != "" {
		if _, found := slices.BinarySearchFunc(r.headIDs, id, compareKeys); found {
			return r.head
		}
	}
	if r.lazyOff != nil {
		r.offOnce.Do(func() { r.lazyOff(r.ctx) })
	}
	if !r.offOK {
		return ""
	}
	if h, found := r.off[id]; found && h.n == 1 {
		return r.names[h.branch]
	}
	return ""
}

// writeWarnings prints one line per bound the resolver has reached and sends
// the ones the off-HEAD walk reaches later to w, once, when it runs. It does
// not start that walk.
func (r *branchResolver) writeWarnings(w io.Writer) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warn = w
	for _, n := range r.notes {
		_, _ = fmt.Fprintln(w, n)
	}
}

// parseCommitKey decodes a lowercase hex commit id into a fixed key: SHA-1
// ids occupy the first 20 bytes. It keeps the whole 32-byte id, unlike
// objectKey, which truncates a SHA-256 id: two commits must never share a key
// here, or one would be given the other's branch.
func parseCommitKey(id string) ([32]byte, bool) {
	var key [32]byte
	if !isObjectID([]byte(id)) {
		return key, false
	}
	_, err := hex.Decode(key[:len(id)/2], []byte(id))
	return key, err == nil
}

// branchShortName maps a ref to the branch short name it stands for, or ""
// for a ref that names no branch: the remote's own HEAD, a remote-tracking
// ref of no configured remote, or anything outside refs/heads and
// refs/remotes. A local and a remote-tracking ref with the same short name
// are one branch.
//
// A remote name may contain "/", so refs/remotes/a/b/c is branch "b/c" of
// remote "a" or branch "c" of remote "a/b". remotes holds the configured
// remote names: the longest one that prefixes the ref wins and the rest,
// slashes included, is the branch. A ref that no configured remote prefixes
// is omitted, never guessed.
func branchShortName(ref string, remotes []string) string {
	if name, ok := strings.CutPrefix(ref, refsHeadsPrefix); ok {
		return name
	}
	rest, ok := strings.CutPrefix(ref, refsRemotesPrefix)
	if !ok {
		return ""
	}
	remote := ""
	for _, r := range remotes {
		if len(r) > len(remote) && strings.HasPrefix(rest, r+"/") {
			remote = r
		}
	}
	if remote == "" {
		return ""
	}
	name := rest[len(remote)+1:]
	if name == "" || name == "HEAD" {
		return ""
	}
	return name
}

// branchBuilder accumulates the walks of one resolver build.
type branchBuilder struct {
	r        *branchResolver
	offLines int // lines streamed by every off-HEAD walk so far
}

// newBranchBuilder starts a resolver for a checked-out branch head ("" when none).
func newBranchBuilder(head string) *branchBuilder {
	return &branchBuilder{r: &branchResolver{head: head, off: make(map[[32]byte]branchHit)}}
}

// finishHead sorts the HEAD set so lookups can bisect it.
func (b *branchBuilder) finishHead() {
	slices.SortFunc(b.r.headIDs, compareKeys)
	b.r.headIDs = slices.Compact(b.r.headIDs)
}

func compareKeys(x, y [32]byte) int { return bytes.Compare(x[:], y[:]) }

// addHead records one commit reachable from HEAD.
func (b *branchBuilder) addHead(id [32]byte) error {
	if len(b.r.headIDs) >= maxHeadCommits {
		return errBranchCap
	}
	b.r.headIDs = append(b.r.headIDs, id)
	return nil
}

// addOff records that the branch with index bi holds a commit HEAD does not.
// Each branch walks once, so an existing entry belongs to another branch.
func (b *branchBuilder) addOff(id [32]byte, bi uint16) error {
	if b.offLines++; b.offLines > maxOffHeadWalkLines {
		return errBranchWalkCap
	}
	h, found := b.r.off[id]
	if !found {
		if len(b.r.off) >= maxOffHeadCommits {
			return errBranchCap
		}
		b.r.off[id] = branchHit{branch: bi, n: 1}
		return nil
	}
	if h.n < ^uint16(0) {
		h.n++
		b.r.off[id] = h
	}
	return nil
}

// branchIndex interns a branch short name. ok is false past the bound.
func (b *branchBuilder) branchIndex(name string) (uint16, bool) {
	if i := slices.Index(b.r.names, name); i >= 0 {
		return uint16(i), true
	}
	if len(b.r.names) >= maxBranches {
		return 0, false
	}
	b.r.names = append(b.r.names, name)
	return uint16(len(b.r.names) - 1), true
}

// unresolvedOff leaves every commit outside HEAD without a branch.
func (b *branchBuilder) unresolvedOff(note string) {
	b.r.withoutOff(note)
}

// overHead is the resolver for a HEAD history over the bound.
func overHead() *branchResolver {
	return &branchResolver{notes: []string{fmt.Sprintf(branchNoteHistoryTooLarge, maxHeadCommits)}}
}

// resolveBranchesNative builds the resolver with the git binary: one
// rev-list of HEAD now, and, on the first lookup of a commit HEAD does not
// hold, one rev-list of each branch with HEAD excluded, all streamed. It
// never fails: whatever cannot be established is left empty.
func resolveBranchesNative(ctx context.Context, root string) *branchResolver {
	head := ""
	if ref, err := symbolicHead(ctx, root); err == nil {
		head = headBranchName(ref)
	}
	b := newBranchBuilder(head)
	if head != "" {
		exists, err := nativeHeadExists(ctx, root)
		switch {
		case err != nil:
			// Without HEAD's history, a branch walk could not tell what the
			// checked-out branch holds: attribute nothing.
			return &branchResolver{notes: []string{branchNoteHeadCheckFailed}}
		case exists:
			if err := nativeRevList(ctx, root, func(id [32]byte) error { return b.addHead(id) }, "rev-list", "HEAD", "--"); err != nil {
				return failedHead(err)
			}
			b.finishHead()
		default:
			b.r.head = "" // unborn: no commit is on HEAD
		}
	}
	b.r.ctx = ctx
	b.r.lazyOff = func(ctx context.Context) { b.offHeadNative(ctx, root) }
	return b.r
}

// offHeadNative fills the off-HEAD part of the resolver.
func (b *branchBuilder) offHeadNative(ctx context.Context, root string) {
	b.r.offOK = true
	tips, err := nativeBranchTips(ctx, root)
	if err != nil {
		b.tipsFailed(err)
		return
	}
	excludeHead := b.r.head != ""
	for _, name := range slices.Sorted(maps.Keys(tips)) {
		bi, ok := b.branchIndex(name)
		if !ok {
			b.unresolvedOff(tooManyBranchesNote())
			return
		}
		args := append([]string{"rev-list"}, tips[name]...)
		if excludeHead {
			args = append(args, "^HEAD")
		}
		// "--" ends the revisions, so a tracked file named like one cannot
		// make git reject the argument as ambiguous.
		args = append(args, "--")
		if err := nativeRevList(ctx, root, func(id [32]byte) error { return b.addOff(id, bi) }, args...); err != nil {
			b.unresolvedOff(offNote(err))
			return
		}
	}
}

func tooManyBranchesNote() string {
	return fmt.Sprintf(offHeadNotePrefix+"more than %d branches", maxBranches)
}

// tipsFailed leaves the off-HEAD part unresolved when the branches could not
// be listed or were over a bound; the HEAD part stays.
func (b *branchBuilder) tipsFailed(err error) {
	switch {
	case errors.Is(err, errBranchRefCap):
		b.r.withoutOff(fmt.Sprintf(offHeadNotePrefix+"more than %d branch refs", maxBranchRefs))
	case errors.Is(err, errBranchCap):
		b.r.withoutOff(tooManyBranchesNote())
	default:
		b.r.withoutOff(offHeadNotePrefix + "could not list branches")
	}
}

// headBranchName is the short name of the local branch a HEAD target ref
// names, or "" when the target is not a local branch.
func headBranchName(ref string) string {
	return strings.TrimPrefix(branchRefOrEmpty(ref), refsHeadsPrefix)
}

// branchRefOrEmpty keeps a ref only when it is a local branch.
func branchRefOrEmpty(ref string) string {
	if strings.HasPrefix(ref, refsHeadsPrefix) {
		return ref
	}
	return ""
}

// failedHead is the resolver when the HEAD walk failed or hit its bound:
// nothing is resolved, since "contains" and "checked out" cannot be told.
func failedHead(err error) *branchResolver {
	if errors.Is(err, errBranchCap) {
		return overHead()
	}
	return &branchResolver{notes: []string{branchNoteHeadUnreadable}}
}

func offNote(err error) string {
	switch {
	case errors.Is(err, errBranchWalkCap):
		return fmt.Sprintf(offHeadNotePrefix+"more than %d commits streamed across the branches' histories", maxOffHeadWalkLines)
	case errors.Is(err, errBranchCap):
		return fmt.Sprintf(offHeadNotePrefix+"more than %d such commits", maxOffHeadCommits)
	}
	return offHeadNotePrefix + "could not read a branch's history"
}

// withoutOff drops the off-HEAD part, keeping the HEAD part.
func (r *branchResolver) withoutOff(note string) *branchResolver {
	r.off, r.offOK = nil, false
	r.addNote(note)
	return r
}

// nativeHeadExists reports whether HEAD names a commit. An unborn branch
// does not, which is not an error; any other failure of the check is.
func nativeHeadExists(ctx context.Context, root string) (bool, error) {
	err := hardenedGit(ctx, root, "rev-parse", "-q", "--verify", "HEAD^{commit}").Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &exit) && exit.ExitCode() == 1: // -q: not a valid object name
		return false, nil
	}
	return false, fmt.Errorf("git rev-parse HEAD: %w", err)
}

// nativeRemoteNames lists the configured remote names.
func nativeRemoteNames(ctx context.Context, root string) ([]string, error) {
	out, err := hardenedGit(ctx, root, "remote").Output()
	if err != nil {
		return nil, fmt.Errorf("git remote: %w", err)
	}
	return strings.Fields(string(out)), nil
}

// nativeBranchTips lists the ref names behind each branch short name. A ref
// naming an object the repository lacks is left out, as goGitBranchTips
// leaves it out: that branch holds no commit we can read. It stops reading
// refs once they name more than maxBranches short names or number more than
// maxBranchRefs, and returns errBranchCap.
func nativeBranchTips(ctx context.Context, root string) (map[string][]string, error) {
	remotes, err := nativeRemoteNames(ctx, root)
	if err != nil {
		return nil, err
	}
	ids, refs, err := nativeBranchRefs(ctx, root, remotes)
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	check := hardenedGit(ctx, root, "cat-file", "--batch-check")
	check.Stdin = strings.NewReader(strings.Join(ids, "\n") + "\n")
	checked, err := check.Output()
	if err != nil {
		return nil, fmt.Errorf("git cat-file: %w", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(checked), "\n"), "\n")
	if len(lines) != len(refs) {
		return nil, fmt.Errorf("git cat-file: %d answers for %d refs", len(lines), len(refs))
	}
	tips := make(map[string][]string)
	for i, ref := range refs {
		if strings.HasSuffix(lines[i], " missing") {
			continue
		}
		name := branchShortName(ref, remotes)
		tips[name] = append(tips[name], ref)
	}
	return tips, nil
}

// nativeBranchRefs streams for-each-ref and returns the object id and ref
// name of every branch ref, stopping with errBranchCap once they name more
// than maxBranches distinct short names, or errBranchRefCap once they number
// more than maxBranchRefs. The patterns are ref names, not
// revisions, so no file can make them ambiguous.
func nativeBranchRefs(ctx context.Context, root string, remotes []string) (ids, refs []string, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := hardenedGit(ctx, root, "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads", "refs/remotes")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("git for-each-ref: pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("git for-each-ref: start: %w", err)
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 4<<10), 64<<10)
	names := make(map[string]struct{})
	var capErr error
	for sc.Scan() {
		id, ref, ok := strings.Cut(sc.Text(), " ")
		name := branchShortName(ref, remotes)
		if !ok || name == "" {
			continue
		}
		names[name] = struct{}{}
		if len(names) > maxBranches {
			capErr = errBranchCap
			break
		}
		if len(refs) >= maxBranchRefs {
			capErr = errBranchRefCap
			break
		}
		ids, refs = append(ids, id), append(refs, ref)
	}
	scanErr := sc.Err()
	if capErr != nil || scanErr != nil {
		cancel()
	}
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	switch {
	case capErr != nil:
		return nil, nil, capErr
	case scanErr != nil:
		return nil, nil, fmt.Errorf("git for-each-ref: %w", scanErr)
	case waitErr != nil:
		return nil, nil, fmt.Errorf("git for-each-ref: %w", waitErr)
	}
	return ids, refs, nil
}

// nativeRevList streams the commit ids git prints for args into each. An
// error from each stops the stream and is returned.
func nativeRevList(ctx context.Context, root string, each func([32]byte) error, args ...string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := hardenedGit(ctx, root, args...)
	stderr := &limitedBuffer{limit: branchRevListStderrLimit}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("git rev-list: pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("git rev-list: start: %w", err)
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, branchIDLineMax), branchIDLineMax)
	var eachErr error
	for sc.Scan() {
		id, ok := parseCommitKey(sc.Text())
		if !ok {
			eachErr = fmt.Errorf("git rev-list: unexpected line")
			break
		}
		if eachErr = each(id); eachErr != nil {
			break
		}
	}
	scanErr := sc.Err()
	if eachErr != nil || scanErr != nil {
		cancel()
	}
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	switch {
	case eachErr != nil:
		return eachErr
	case scanErr != nil:
		return fmt.Errorf("git rev-list: %w", scanErr)
	case waitErr != nil:
		return fmt.Errorf("git rev-list: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// resolveBranchesGoGit builds the same resolver as resolveBranchesNative
// without the git binary. It walks the commit graph itself, as
// goGitHistoryIndex does, so a shallow commit is a root as it is for git.
func resolveBranchesGoGit(ctx context.Context, repo *git.Repository) *branchResolver {
	head := ""
	var headHash plumbing.Hash
	if ref, err := repo.Reference(plumbing.HEAD, false); err == nil && ref.Type() == plumbing.SymbolicReference {
		head = headBranchName(ref.Target().String())
	}
	if head != "" {
		h, err := repo.ResolveRevision("HEAD^{commit}")
		switch {
		case err == nil:
			headHash = *h
		case errors.Is(err, plumbing.ErrReferenceNotFound):
			head = "" // unborn: no commit is on HEAD
		default:
			return &branchResolver{notes: []string{branchNoteHeadCheckFailed}}
		}
	}
	shallow, err := goGitShallow(repo)
	if err != nil {
		return &branchResolver{}
	}
	b := newBranchBuilder(head)
	var headSet map[plumbing.Hash]struct{}
	if head != "" {
		headSet = make(map[plumbing.Hash]struct{})
		err := walkGoGitCommits(ctx, repo, []plumbing.Hash{headHash}, shallow, nil, func(h plumbing.Hash) error {
			headSet[h] = struct{}{}
			return b.addHead(hashKey(h))
		})
		if err != nil {
			return failedHead(err)
		}
		b.finishHead()
	}
	b.r.ctx = ctx
	b.r.lazyOff = func(ctx context.Context) { b.offHeadGoGit(ctx, repo, shallow, headSet) }
	return b.r
}

// offHeadGoGit fills the off-HEAD part of the resolver.
func (b *branchBuilder) offHeadGoGit(ctx context.Context, repo *git.Repository, shallow, headSet map[plumbing.Hash]struct{}) {
	b.r.offOK = true
	tips, err := goGitBranchTips(repo)
	if err != nil {
		b.tipsFailed(err)
		return
	}
	for _, name := range slices.Sorted(maps.Keys(tips)) {
		bi, ok := b.branchIndex(name)
		if !ok {
			b.unresolvedOff(tooManyBranchesNote())
			return
		}
		err := walkGoGitCommits(ctx, repo, tips[name], shallow, headSet, func(h plumbing.Hash) error {
			return b.addOff(hashKey(h), bi)
		})
		if err != nil {
			b.unresolvedOff(offNote(err))
			return
		}
	}
}

func hashKey(h plumbing.Hash) [32]byte {
	var k [32]byte
	copy(k[:], h[:])
	return k
}

func goGitShallow(repo *git.Repository) (map[plumbing.Hash]struct{}, error) {
	list, err := repo.Storer.Shallow()
	if err != nil {
		return nil, err
	}
	set := make(map[plumbing.Hash]struct{}, len(list))
	for _, h := range list {
		set[h] = struct{}{}
	}
	return set, nil
}

// goGitBranchTips lists the commit behind each ref of each branch short name.
// It stops at more than maxBranches short names, or more than maxBranchRefs
// refs, and returns errBranchCap or errBranchRefCap.
func goGitBranchTips(repo *git.Repository) (map[string][]plumbing.Hash, error) {
	cfg, err := repo.Config()
	if err != nil {
		return nil, err
	}
	remotes := slices.Collect(maps.Keys(cfg.Remotes))
	iter, err := repo.References()
	if err != nil {
		return nil, err
	}
	tips := make(map[string][]plumbing.Hash)
	refCount := 0
	err = iter.ForEach(func(ref *plumbing.Reference) error {
		if ref.Type() != plumbing.HashReference {
			return nil
		}
		name := branchShortName(ref.Name().String(), remotes)
		if name == "" || ref.Hash().IsZero() {
			return nil
		}
		// git for-each-ref skips a ref whose object is missing: such a
		// branch holds no commit we can read.
		if _, err := object.GetCommit(repo.Storer, ref.Hash()); errors.Is(err, plumbing.ErrObjectNotFound) {
			return nil
		}
		tips[name] = append(tips[name], ref.Hash())
		if len(tips) > maxBranches {
			return errBranchCap
		}
		if refCount++; refCount > maxBranchRefs {
			return errBranchRefCap
		}
		return nil
	})
	return tips, err
}

// walkGoGitCommits calls each once for every commit reachable from tips
// that is not in ignore and not behind one in ignore, as rev-list does with
// "^HEAD": an ignored commit and its ancestors are never visited by the
// walk, because HEAD's set is closed under ancestry.
func walkGoGitCommits(ctx context.Context, repo *git.Repository, tips []plumbing.Hash, shallow, ignore map[plumbing.Hash]struct{}, each func(plumbing.Hash) error) error {
	seen := make(map[plumbing.Hash]struct{})
	stack := slices.Clone(tips)
	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		h := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		if _, ok := ignore[h]; ok {
			continue
		}
		c, err := object.GetCommit(repo.Storer, h)
		if err != nil {
			return fmt.Errorf("failed to get commit %s: %w", h, err)
		}
		if err := each(h); err != nil {
			return err
		}
		if _, isShallow := shallow[h]; !isShallow {
			stack = append(stack, c.ParentHashes...)
		}
	}
	return nil
}

// singleCommitBranch resolves the branch of the one commit a single-commit
// scan reads. A commit that is HEAD itself needs no set: it is on the
// checked-out branch when HEAD is on one.
func singleCommitBranch(ctx context.Context, repo *git.Repository, root string, commit plumbing.Hash, warn io.Writer) string {
	if ref, err := repo.Reference(plumbing.HEAD, false); err == nil && ref.Type() == plumbing.SymbolicReference {
		if name := headBranchName(ref.Target().String()); name != "" {
			if h, err := repo.ResolveRevision("HEAD^{commit}"); err == nil && *h == commit {
				return name
			}
		}
	}
	var r *branchResolver
	if gitBinaryAvailable() {
		r = resolveBranchesNative(ctx, root)
	} else {
		r = resolveBranchesGoGit(ctx, repo)
	}
	r.writeWarnings(warn)
	return r.of(commit.String())
}
