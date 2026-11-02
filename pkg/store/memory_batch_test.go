package store

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ENG-9178: scan workers check then insert a finding inside one ExecBatch
// (FindingExists, then AddFinding when it is new). SQLiteStore runs each batch
// in a transaction, so the pair is atomic. MemoryStore must give the same
// guarantee: a second batch may not enter its fn while the first is still
// running, or both see the finding as new and both count it.
func TestMemoryStore_ExecBatchSerializesCheckThenInsert(t *testing.T) {
	const findingID = "finding-1"
	s := NewMemory()

	var sawNew atomic.Int32
	// checkThenInsert is the scan.go batch body: count the finding as new and
	// add it only when FindingExists says it is absent.
	checkThenInsert := func(tx Store) error {
		exists, err := tx.FindingExists(findingID)
		if err != nil {
			return err
		}
		if !exists {
			sawNew.Add(1)
			return tx.AddFinding(&types.Finding{ID: findingID, RuleID: "np.github.1"})
		}
		return nil
	}

	parked := make(chan struct{})
	release := make(chan struct{})
	done1 := make(chan error, 1)
	go func() {
		done1 <- s.ExecBatch(func(tx Store) error {
			exists, err := tx.FindingExists(findingID)
			if err != nil {
				return err
			}
			close(parked)
			<-release
			if !exists {
				sawNew.Add(1)
				return tx.AddFinding(&types.Finding{ID: findingID, RuleID: "np.github.1"})
			}
			return nil
		})
	}()

	select {
	case <-parked:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "batch 1 never entered its fn")
	}

	entered2 := make(chan struct{})
	done2 := make(chan error, 1)
	go func() {
		done2 <- s.ExecBatch(func(tx Store) error {
			close(entered2)
			return checkThenInsert(tx)
		})
	}()

	// While batch 1 is parked between its check and its insert, batch 2 must
	// not run. The wait is bounded; an early entry is the defect.
	select {
	case <-entered2:
		assert.Fail(t, "batch 2 entered its fn while batch 1 was still running")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	for name, done := range map[string]chan error{"batch 1": done1, "batch 2": done2} {
		select {
		case err := <-done:
			require.NoError(t, err, name)
		case <-time.After(5 * time.Second):
			require.FailNow(t, name+" did not finish")
		}
	}

	assert.Equal(t, int32(1), sawNew.Load(), "batches that saw the finding as new")
	findings, err := s.GetFindings()
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, findingID, findings[0].ID)
}
