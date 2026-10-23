package store

import (
	"fmt"
	"sync"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// blobRecord stores blob metadata.
type blobRecord struct {
	id   types.BlobID
	size int64
}

// MemoryStore implements Store using in-memory data structures.
// No CGO dependency required.
// Originally used only for WASM builds, but now the default for non-CGO builds.
type MemoryStore struct {
	mu         sync.RWMutex
	blobs      map[string]blobRecord         // keyed by BlobID.Hex()
	matches    []*types.Match                // all matches
	findings   map[string]*types.Finding     // keyed by structural_id
	provenance map[string][]types.Provenance // keyed by BlobID.Hex()
	provKeys   map[provenanceKey]struct{}    // mirrors the SQLite provenance UNIQUE key

	occurrences  map[string][]types.Occurrence // keyed by BlobID.Hex()
	locationKeys map[locationKey]struct{}      // mirrors the blob_locations UNIQUE key
}

// provenanceKey is the in-memory twin of the provenance table's UNIQUE key.
type provenanceKey struct {
	blob string
	provenanceRowKey
}

// locationKey is the in-memory twin of the blob_locations UNIQUE key.
type locationKey struct {
	blob, kind, repository, path, absolutePath, commit string
	workingTree                                        bool
}

// NewMemory creates a new in-memory store.
func NewMemory() *MemoryStore {
	return &MemoryStore{
		blobs:        make(map[string]blobRecord),
		matches:      make([]*types.Match, 0),
		findings:     make(map[string]*types.Finding),
		provenance:   make(map[string][]types.Provenance),
		provKeys:     make(map[provenanceKey]struct{}),
		occurrences:  make(map[string][]types.Occurrence),
		locationKeys: make(map[locationKey]struct{}),
	}
}

// AddBlob stores a blob record.
func (m *MemoryStore) AddBlob(id types.BlobID, size int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := id.Hex()
	if _, exists := m.blobs[key]; exists {
		// Idempotent - already exists
		return nil
	}

	m.blobs[key] = blobRecord{
		id:   id,
		size: size,
	}
	return nil
}

// AddRule stores a detection rule.
// Memory store doesn\'t enforce foreign key constraints, so this is a no-op.
func (m *MemoryStore) AddRule(r *types.Rule) error {
	return nil
}

// AddMatch stores a match record.
func (m *MemoryStore) AddMatch(match *types.Match) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.matches = append(m.matches, match)
	return nil
}

// AddFinding stores a finding (deduplicated).
func (m *MemoryStore) AddFinding(f *types.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.findings[f.ID]; exists {
		// Deduplicate - already exists
		return nil
	}

	m.findings[f.ID] = f
	return nil
}

// AddProvenance associates provenance with a blob.
func (m *MemoryStore) AddProvenance(blobID types.BlobID, prov types.Provenance) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rowKey, err := provenanceKeyOf(prov)
	if err != nil {
		return err
	}
	key := blobID.Hex()
	pk := provenanceKey{blob: key, provenanceRowKey: rowKey}
	if _, exists := m.provKeys[pk]; exists {
		return nil
	}
	m.provKeys[pk] = struct{}{}
	m.provenance[key] = append(m.provenance[key], storedProvenance(prov))
	return nil
}

// storedProvenance drops the GitProvenance fields the SQLite provenance table
// does not persist, so both stores return the same rows. Locations now live in
// the occurrence rows.
func storedProvenance(prov types.Provenance) types.Provenance {
	g, ok := prov.(types.GitProvenance)
	if !ok {
		return prov
	}
	g.Locations = nil
	g.RepoRoot = ""
	g.RemoteIdentity = false
	return g
}

// AddOccurrences stores every occurrence of a blob, ignoring duplicates of the
// blob_locations UNIQUE key.
func (m *MemoryStore) AddOccurrences(blobID types.BlobID, occs []types.Occurrence) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := blobID.Hex()
	for _, o := range occs {
		lk := locationKey{
			blob: key, kind: o.Kind, repository: o.Repository, path: o.Path,
			absolutePath: o.AbsolutePath, commit: o.Commit, workingTree: o.WorkingTree,
		}
		if _, exists := m.locationKeys[lk]; exists {
			continue
		}
		m.locationKeys[lk] = struct{}{}
		o.HostRecorded = true
		if o.CommitDate.IsZero() {
			o.CommitDate = time.Time{}
		} else {
			o.CommitDate = time.Unix(o.CommitDate.Unix(), 0).UTC()
		}
		m.occurrences[key] = append(m.occurrences[key], o)
	}
	return nil
}

// GetOccurrences returns the stored occurrences of a blob merged with its
// legacy provenance rows, deduplicated and sorted.
func (m *MemoryStore) GetOccurrences(blobID types.BlobID) ([]types.Occurrence, error) {
	m.mu.RLock()
	key := blobID.Hex()
	rows := append([]types.Occurrence(nil), m.occurrences[key]...)
	provs := append([]types.Provenance(nil), m.provenance[key]...)
	m.mu.RUnlock()

	return mergedOccurrences(rows, provs), nil
}

// GetAllProvenance retrieves all provenance records for a blob.
func (m *MemoryStore) GetAllProvenance(blobID types.BlobID) ([]types.Provenance, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := blobID.Hex()
	provs := m.provenance[key]
	if provs == nil {
		return []types.Provenance{}, nil
	}

	// Return a copy to avoid external modifications
	result := make([]types.Provenance, len(provs))
	copy(result, provs)
	return result, nil
}

// GetMatches retrieves matches for a blob.
func (m *MemoryStore) GetMatches(blobID types.BlobID) ([]*types.Match, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*types.Match
	for _, match := range m.matches {
		if match.BlobID.Hex() == blobID.Hex() {
			result = append(result, match)
		}
	}

	if result == nil {
		return []*types.Match{}, nil
	}

	return result, nil
}

// GetAllMatches retrieves all matches (for JSON export).
func (m *MemoryStore) GetAllMatches() ([]*types.Match, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to avoid external modifications
	result := make([]*types.Match, len(m.matches))
	copy(result, m.matches)
	return result, nil
}

// GetFindings retrieves all findings (for reporting).
func (m *MemoryStore) GetFindings() ([]*types.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*types.Finding, 0, len(m.findings))
	for _, finding := range m.findings {
		result = append(result, finding)
	}
	return result, nil
}

// FindingExists checks if a finding with this structural ID exists.
func (m *MemoryStore) FindingExists(structuralID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.findings[structuralID]
	return exists, nil
}

// BlobExists checks if a blob has already been scanned.
func (m *MemoryStore) BlobExists(id types.BlobID) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.blobs[id.Hex()]
	return exists, nil
}

// GetProvenance retrieves provenance for a blob.
func (m *MemoryStore) GetProvenance(blobID types.BlobID) (types.Provenance, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := blobID.Hex()
	provs := m.provenance[key]
	if len(provs) == 0 {
		return nil, fmt.Errorf("no provenance found for blob %s", key)
	}

	// Return the first provenance record
	return provs[0], nil
}

func (s *MemoryStore) ExecBatch(fn func(Store) error) error {
	return fn(s)
}

// GetAnnotation is a no-op for in-memory store.
func (m *MemoryStore) GetAnnotation(targetType, targetID string) (string, string, error) {
	return "", "", nil
}

// SetAnnotation is a no-op for in-memory store.
func (m *MemoryStore) SetAnnotation(targetType, targetID, status, comment string) error {
	return nil
}

// GetAnnotationsByType is a no-op for in-memory store.
func (m *MemoryStore) GetAnnotationsByType(targetType string) (map[string]string, error) {
	return map[string]string{}, nil
}

// Close closes the database connection.
// For in-memory store, this is a no-op.
func (m *MemoryStore) Close() error {
	// No resources to clean up for in-memory store
	return nil
}
