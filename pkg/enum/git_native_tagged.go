package enum

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
)

// taggedTreeBlobs returns the blobs under every tree that a ref, or HEAD,
// points at directly or through annotated tags, the number of such refs, and
// the number of linked worktrees whose HEAD git could not read (R5-3).
// rev-list lists a blob under such a tree at the first path it reaches it by
// and git log never sees the tree, so the blob's other paths are unknown.
// Every path under a tagged tree is not listed: a tree that names one subtree
// many times has exponentially many paths (ENG-9329). The blobs are found
// with one rev-list over the trees, which reads each object once.
func taggedTreeBlobs(ctx context.Context, dir string) (map[[20]byte]struct{}, int, int, error) {
	tips, err := resolveRefTips(ctx, dir)
	if err != nil {
		return nil, 0, 0, err
	}
	if len(tips.trees) == 0 {
		return nil, 0, tips.lost, nil
	}
	var in bytes.Buffer
	for _, t := range tips.trees {
		in.WriteString(t)
		in.WriteByte('\n')
	}
	// Missing objects are listed, not fetched or fatal; rev-list --all
	// already counts and reports them, so this walk's counts are not used.
	rl, err := runRevList(ctx, dir, &in, "rev-list", "--objects", "--missing=print", "--stdin")
	if err != nil {
		return nil, 0, 0, fmt.Errorf("tagged trees: %w", err)
	}
	blobs := make(map[[20]byte]struct{}, len(rl.blobs))
	for _, b := range rl.blobs {
		blobs[b.hash] = struct{}{}
	}
	return blobs, len(tips.trees), tips.lost, nil
}

// refTips are the objects rev-list --all starts from, peeled through
// annotated tags and limited to objects in the repository.
type refTips struct {
	// commits are the commits, in rev-list --all order: refs by name,
	// then HEAD, then the HEAD of each other worktree.
	commits []string
	// trees holds one tree id per ref that peels to a tree. HEAD counts
	// only when it is not a symbolic ref to a listed ref, so one ref is
	// never counted twice. A worktree HEAD that names a tree adds it when
	// it is not already listed.
	trees []string
	// lost counts linked worktrees whose HEAD git could not read, so the
	// commits only that HEAD reaches are not among the tips (R5-3).
	lost int
}

// tipKind says what a line of the cat-file batch in resolveRefTips is for.
type tipKind uint8

const (
	tipRef      tipKind = iota // a ref: a commit or a tree
	tipHead                    // HEAD: a commit, or a tree when not a symref to a listed ref
	tipHeadDup                 // HEAD as a symref to a listed ref: a commit only
	tipWorktree                // a worktree's HEAD: a commit, or a tree not already listed
)

// resolveRefTips returns what rev-list --all starts from, without its
// failures: git log --all stops at the first broken ref ("fatal: bad
// object"), where rev-list and go-git skip it. for-each-ref skips a ref
// whose file is not an object id, and cat-file drops a ref to a missing
// object, so only commits and trees in the repository are returned.
func resolveRefTips(ctx context.Context, dir string) (refTips, error) {
	refs, err := hardenedGit(ctx, dir, "for-each-ref", "--format=%(objectname) %(refname)").Output()
	if err != nil {
		return refTips{}, fmt.Errorf("git for-each-ref: %w", err)
	}
	head, err := symbolicHead(ctx, dir)
	if err != nil {
		return refTips{}, err
	}
	worktrees, lost, err := worktreeHeads(ctx, dir)
	if err != nil {
		return refTips{}, err
	}

	var (
		in    bytes.Buffer
		kinds []tipKind
		dup   bool
	)
	for _, line := range strings.Split(string(refs), "\n") {
		id, name, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		dup = dup || (head != "" && name == head)
		in.WriteString(id)
		in.WriteString("^{}\n")
		kinds = append(kinds, tipRef)
	}
	in.WriteString("HEAD^{}\n")
	if dup {
		kinds = append(kinds, tipHeadDup)
	} else {
		kinds = append(kinds, tipHead)
	}
	for _, id := range worktrees {
		in.WriteString(id)
		in.WriteString("^{}\n")
		kinds = append(kinds, tipWorktree)
	}

	cmd := hardenedGit(ctx, dir, "cat-file", "--batch-check=%(objecttype) %(objectname)")
	cmd.Stdin = &in
	out, err := cmd.Output()
	if err != nil {
		return refTips{}, fmt.Errorf("git cat-file: %w", err)
	}
	t := refTips{lost: lost}
	commits := make(map[string]struct{}) // a tip named twice is listed once
	for i, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		if i >= len(kinds) {
			break
		}
		typ, id, ok := strings.Cut(line, " ")
		if !ok || revListIDWidth([]byte(id)) != len(id) {
			continue // "<name> missing", or an ambiguous name
		}
		switch {
		case typ == "commit":
			if _, ok := commits[id]; !ok {
				commits[id] = struct{}{}
				t.commits = append(t.commits, id)
			}
		case typ == "tree" && (kinds[i] == tipRef || kinds[i] == tipHead):
			t.trees = append(t.trees, id)
		case typ == "tree" && kinds[i] == tipWorktree && !slices.Contains(t.trees, id):
			// git accepts a tree in a worktree's HEAD and walks it, as
			// go-git does (R5-2). worktree list also names the opened
			// worktree and resolves a HEAD on a branch, which repeat HEAD
			// or a ref, so a tree already listed is not counted again.
			t.trees = append(t.trees, id)
		}
	}
	return t, nil
}

// symbolicHead returns the ref HEAD points at, or "" when HEAD is detached.
func symbolicHead(ctx context.Context, dir string) (string, error) {
	out, err := hardenedGit(ctx, dir, "symbolic-ref", "-q", "HEAD").Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return "", nil // detached HEAD
	}
	if err != nil {
		return "", fmt.Errorf("git symbolic-ref: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// worktreeHeads returns the HEAD commit id of every worktree, which
// rev-list --all also starts from, and the number of worktrees whose HEAD
// git could not read. A worktree on a branch repeats a ref and costs
// nothing; a detached one adds commits no ref reaches.
//
// A worktree path may contain a newline, so the plain porcelain output
// can carry a forged "HEAD <id>" line. With -z (git 2.36 or later) every
// field ends in NUL and a path is one field, so the HEAD field that
// follows a worktree field is the real one. An older git rejects -z with
// exit 129; worktreeHeadsLines then parses the plain output.
//
// git prints the null id for a HEAD it cannot read, with no branch line,
// and exits 0. That worktree is counted as lost, as go-git counts one
// (R5-3). An unborn branch also has the null id, but it has a branch line
// and no commits, so it is not counted; a bare entry has no HEAD.
func worktreeHeads(ctx context.Context, dir string) ([]string, int, error) {
	out, err := hardenedGit(ctx, dir, "worktree", "list", "--porcelain", "-z").Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 129 {
		return worktreeHeadsLines(ctx, dir)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("git worktree list: %w", err)
	}
	var (
		ids  []string
		lost int
		// The state of the current block: inBlock until its empty field.
		inBlock, haveHead, nullHead, branch bool
	)
	end := func() {
		if inBlock && nullHead && !branch {
			lost++
		}
		inBlock = false
	}
	for _, field := range strings.Split(string(out), "\x00") {
		switch {
		case field == "":
			end() // an empty field ends a block
		case strings.HasPrefix(field, "worktree "):
			end()
			inBlock, haveHead, nullHead, branch = true, false, false, false
		case !inBlock:
		case strings.HasPrefix(field, "branch "):
			branch = true
		case !haveHead:
			if id, ok := strings.CutPrefix(field, "HEAD "); ok {
				haveHead = true
				nullHead = isNullID(id)
				ids = appendWorktreeHead(ids, id)
			}
		}
	}
	end()
	return ids, lost, nil
}

// worktreeHeadsLines parses "worktree list --porcelain" for a git older
// than 2.36. Without -z a worktree path can hold a newline, so neither a
// block boundary nor the order of lines can be trusted: a blank line in a
// path ends a block early and a forged line can come first (R5-4). Every
// "HEAD <id>" line is therefore kept, wherever it is. This only adds tips:
// an id must be strict hex and name an object that exists, and cat-file
// drops the rest, so no real tip is lost.
//
// A null "HEAD" line with no "branch" line after it, before the next blank
// or "worktree" line, counts as a lost worktree HEAD (R5-3). A forged line
// can only add to that count, which marks more findings, never fewer.
func worktreeHeadsLines(ctx context.Context, dir string) ([]string, int, error) {
	out, err := hardenedGit(ctx, dir, "worktree", "list", "--porcelain").Output()
	if err != nil {
		return nil, 0, fmt.Errorf("git worktree list: %w", err)
	}
	var (
		ids     []string
		lost    int
		pending bool // a null HEAD line waits for a branch line
	)
	for _, line := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(line, "HEAD "):
			if pending {
				lost++
			}
			id := strings.TrimPrefix(line, "HEAD ")
			pending = isNullID(id)
			ids = appendWorktreeHead(ids, id)
		case strings.HasPrefix(line, "branch "):
			pending = false
		case line == "" || strings.HasPrefix(line, "worktree "):
			if pending {
				lost++
			}
			pending = false
		}
	}
	if pending {
		lost++
	}
	return ids, lost, nil
}

// isNullID reports whether id is the null object id of either width.
func isNullID(id string) bool {
	return (len(id) == 40 || len(id) == 64) && strings.Trim(id, "0") == ""
}

// appendWorktreeHead appends id when it is a full object id that is not
// the null id (an unborn branch).
func appendWorktreeHead(ids []string, id string) []string {
	if revListIDWidth([]byte(id)) == len(id) && strings.Trim(id, "0") != "" {
		ids = append(ids, id)
	}
	return ids
}
