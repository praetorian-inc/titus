package store

import (
	"fmt"
	"sync"

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
	blobs      map[string]blobRecord        // keyed by BlobID.Hex()
	matches    []*types.Match               // all matches
	findings   map[string]*types.Finding    // keyed by structural_id
	provenance map[string][]types.Provenance // keyed by BlobID.Hex()
}

// NewMemory creates a new in-memory store.
func NewMemory() *MemoryStore {
	return &MemoryStore{
		blobs:      make(map[string]blobRecord),
		matches:    make([]*types.Match, 0),
		findings:   make(map[string]*types.Finding),
		provenance: make(map[string][]types.Provenance),
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

	key := blobID.Hex()

	// Check for duplicate provenance (simple deduplication)
	existing := m.provenance[key]
	for _, p := range existing {
		// Check if this provenance is already stored
		// This is a simplified check - in production you might want more sophisticated comparison
		if fmt.Sprintf("%#v", p) == fmt.Sprintf("%#v", prov) {
			return nil
		}
	}

	m.provenance[key] = append(m.provenance[key], prov)
	return nil
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

// Close closes the database connection.
// For in-memory store, this is a no-op.
func (m *MemoryStore) Close() error {
	// No resources to clean up for in-memory store
	return nil
}
