package enum

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// taggedTreeBlobs returns the blobs under every tree that a ref, or HEAD,
// points at directly or through annotated tags, and the number of such refs.
// rev-list lists a blob under such a tree at the first path it reaches it by
// and git log never sees the tree, so the blob's other paths are unknown.
// Every path under a tagged tree is not listed: a tree that names one subtree
// many times has exponentially many paths (ENG-9329). The blobs are found
// with one rev-list over the trees, which reads each object once.
func taggedTreeBlobs(ctx context.Context, dir string) (map[[20]byte]struct{}, int, error) {
	trees, err := taggedTrees(ctx, dir)
	if err != nil || len(trees) == 0 {
		return nil, 0, err
	}
	var in bytes.Buffer
	for _, t := range trees {
		in.WriteString(t)
		in.WriteByte('\n')
	}
	// Missing objects are listed, not fetched or fatal; rev-list --all
	// already counts and reports them, so this walk's counts are not used.
	rl, err := runRevList(ctx, dir, &in, "rev-list", "--objects", "--missing=print", "--stdin")
	if err != nil {
		return nil, 0, fmt.Errorf("tagged trees: %w", err)
	}
	blobs := make(map[[20]byte]struct{}, len(rl.blobs))
	for _, b := range rl.blobs {
		blobs[b.hash] = struct{}{}
	}
	return blobs, len(trees), nil
}

// taggedTrees returns the tree id of each ref, and of HEAD, that peels to a
// tree, once per ref. A ref to a missing object is skipped, as rev-list
// skips it.
func taggedTrees(ctx context.Context, dir string) ([]string, error) {
	t, err := resolveRefTips(ctx, dir)
	if err != nil {
		return nil, err
	}
	return t.trees, nil
}

// refTips are the objects rev-list --all starts from, peeled through
// annotated tags and limited to objects in the repository.
type refTips struct {
	// commits are the commits, in rev-list --all order: refs by name,
	// then HEAD, then the HEAD of each other worktree.
	commits []string
	// trees holds one tree id per ref that peels to a tree. HEAD counts
	// only when it is not a symbolic ref to a listed ref, so one ref is
	// never counted twice.
	trees []string
}

// tipKind says what a line of the cat-file batch in resolveRefTips is for.
type tipKind uint8

const (
	tipRef      tipKind = iota // a ref: a commit or a tree
	tipHead                    // HEAD: a commit, or a tree when not a symref to a listed ref
	tipHeadDup                 // HEAD as a symref to a listed ref: a commit only
	tipWorktree                // another worktree's HEAD: a commit only
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
	worktrees, err := worktreeHeads(ctx, dir)
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
	var t refTips
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
			t.commits = append(t.commits, id)
		case typ == "tree" && (kinds[i] == tipRef || kinds[i] == tipHead):
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
// rev-list --all also starts from. A worktree on a branch repeats a ref
// and costs nothing; a detached one adds commits no ref reaches.
func worktreeHeads(ctx context.Context, dir string) ([]string, error) {
	out, err := hardenedGit(ctx, dir, "worktree", "list", "--porcelain").Output()
	if err != nil {
		return nil, fmt.Errorf("git worktree list: %w", err)
	}
	var ids []string
	for _, line := range strings.Split(string(out), "\n") {
		id, ok := strings.CutPrefix(line, "HEAD ")
		if ok && revListIDWidth([]byte(id)) == len(id) && strings.Trim(id, "0") != "" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}
