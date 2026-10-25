package enum

import (
	"bytes"
	"context"
	"fmt"
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
	refs, err := hardenedGit(ctx, dir, "for-each-ref", "--format=%(objectname)").Output()
	if err != nil {
		return nil, fmt.Errorf("git for-each-ref: %w", err)
	}
	var in bytes.Buffer
	for _, id := range strings.Fields(string(refs)) {
		in.WriteString(id)
		in.WriteString("^{}\n")
	}
	in.WriteString("HEAD^{}\n")

	cmd := hardenedGit(ctx, dir, "cat-file", "--batch-check=%(objecttype) %(objectname)")
	cmd.Stdin = &in
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git cat-file: %w", err)
	}
	var trees []string
	for _, line := range strings.Split(string(out), "\n") {
		if id, ok := strings.CutPrefix(line, "tree "); ok {
			trees = append(trees, id)
		}
	}
	return trees, nil
}
