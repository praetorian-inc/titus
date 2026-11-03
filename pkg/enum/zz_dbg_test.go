package enum

import (
	"fmt"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
)

func TestZZDbg(t *testing.T) {
	dir := brInit(t)
	c1 := brCommit(t, dir, "c1")
	corruptObject(t, dir, c1)
	repo, _ := openGoGitRepo(dir)
	h, err := repo.ResolveRevision("HEAD^{commit}")
	fmt.Println("resolve", h, err)
	_, err = repo.CommitObject(plumbing.NewHash(c1))
	fmt.Println("commit", err)
}
