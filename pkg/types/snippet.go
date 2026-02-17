package types

// Snippet contains context around a match.
type Snippet struct {
	Before   []byte // bytes before match
	Matching []byte // the matched content
	After    []byte // bytes after match
}
