// Package store persists annotations, findings, matches, and related scan data.
//
// This file defines canonical values for annotation fields so callers don't
// have to hardcode string literals.
package store

// Annotation status values for findings and matches. Used with SetAnnotation
// and returned from GetAnnotation.
const (
	// StatusAccept marks a finding or match as accepted (a true positive).
	StatusAccept = "accept"
	// StatusReject marks a finding or match as rejected (a false positive).
	// Rejected findings are hidden from `titus report` by default.
	StatusReject = "reject"
)
