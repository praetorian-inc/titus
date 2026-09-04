package types

// ResourceInfo describes a specific resource accessible via a detected credential.
// Populated as a best-effort side-effect of scorer API calls — fields are only
// set when the upstream API returns them.
type ResourceInfo struct {
	Service string `json:"service"`
	Type    string `json:"type"`
	Name    string `json:"name,omitempty"`
	Count   int    `json:"count,omitempty"`
	Region  string `json:"region,omitempty"`
}
