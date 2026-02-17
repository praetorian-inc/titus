package rule

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePatterns(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string returns empty slice",
			input:    "",
			expected: []string{},
		},
		{
			name:     "single pattern",
			input:    "aws.*",
			expected: []string{"aws.*"},
		},
		{
			name:     "multiple patterns comma-separated",
			input:    "aws.*,github.*,token",
			expected: []string{"aws.*", "github.*", "token"},
		},
		{
			name:     "patterns with spaces are trimmed",
			input:    " aws.* , github.* , token ",
			expected: []string{"aws.*", "github.*", "token"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePatterns(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFilter_IncludeOnly(t *testing.T) {
	rules := []*types.Rule{
		{ID: "np.aws.1", Name: "AWS Access Key"},
		{ID: "np.aws.2", Name: "AWS Secret Key"},
		{ID: "np.github.1", Name: "GitHub Token"},
		{ID: "np.token.1", Name: "Generic Token"},
	}

	tests := []struct {
		name     string
		include  []string
		expected []string // expected rule IDs
	}{
		{
			name:     "include AWS rules only",
			include:  []string{"np.aws.*"},
			expected: []string{"np.aws.1", "np.aws.2"},
		},
		{
			name:     "include multiple patterns",
			include:  []string{"np.aws.*", "np.github.*"},
			expected: []string{"np.aws.1", "np.aws.2", "np.github.1"},
		},
		{
			name:     "include exact match",
			include:  []string{"np.aws.1"},
			expected: []string{"np.aws.1"},
		},
		{
			name:     "include pattern matches none",
			include:  []string{"np.nomatch.*"},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := FilterConfig{
				Include: tt.include,
			}

			filtered, err := Filter(rules, config)
			require.NoError(t, err)

			resultIDs := make([]string, 0)
			for _, r := range filtered {
				resultIDs = append(resultIDs, r.ID)
			}

			assert.Equal(t, tt.expected, resultIDs)
		})
	}
}

func TestFilter_ExcludeOnly(t *testing.T) {
	rules := []*types.Rule{
		{ID: "np.aws.1", Name: "AWS Access Key"},
		{ID: "np.aws.2", Name: "AWS Secret Key"},
		{ID: "np.github.1", Name: "GitHub Token"},
		{ID: "np.token.1", Name: "Generic Token"},
	}

	tests := []struct {
		name     string
		exclude  []string
		expected []string // expected rule IDs
	}{
		{
			name:     "exclude AWS rules",
			exclude:  []string{"np.aws.*"},
			expected: []string{"np.github.1", "np.token.1"},
		},
		{
			name:     "exclude multiple patterns",
			exclude:  []string{"np.aws.*", "np.github.*"},
			expected: []string{"np.token.1"},
		},
		{
			name:     "exclude exact match",
			exclude:  []string{"np.aws.1"},
			expected: []string{"np.aws.2", "np.github.1", "np.token.1"},
		},
		{
			name:     "exclude pattern matches none",
			exclude:  []string{"np.nomatch.*"},
			expected: []string{"np.aws.1", "np.aws.2", "np.github.1", "np.token.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := FilterConfig{
				Exclude: tt.exclude,
			}

			filtered, err := Filter(rules, config)
			require.NoError(t, err)

			resultIDs := make([]string, 0)
			for _, r := range filtered {
				resultIDs = append(resultIDs, r.ID)
			}

			assert.Equal(t, tt.expected, resultIDs)
		})
	}
}

func TestFilter_IncludeAndExclude(t *testing.T) {
	rules := []*types.Rule{
		{ID: "np.aws.1", Name: "AWS Access Key"},
		{ID: "np.aws.2", Name: "AWS Secret Key"},
		{ID: "np.aws.deprecated.1", Name: "AWS Deprecated"},
		{ID: "np.github.1", Name: "GitHub Token"},
	}

	tests := []struct {
		name     string
		include  []string
		exclude  []string
		expected []string // expected rule IDs
	}{
		{
			name:     "include AWS then exclude deprecated",
			include:  []string{"np.aws.*"},
			exclude:  []string{".*deprecated.*"},
			expected: []string{"np.aws.1", "np.aws.2"},
		},
		{
			name:     "include all then exclude AWS",
			include:  []string{".*"},
			exclude:  []string{"np.aws.*"},
			expected: []string{"np.github.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := FilterConfig{
				Include: tt.include,
				Exclude: tt.exclude,
			}

			filtered, err := Filter(rules, config)
			require.NoError(t, err)

			resultIDs := make([]string, 0)
			for _, r := range filtered {
				resultIDs = append(resultIDs, r.ID)
			}

			assert.Equal(t, tt.expected, resultIDs)
		})
	}
}

func TestFilter_EmptyPatterns(t *testing.T) {
	rules := []*types.Rule{
		{ID: "np.aws.1", Name: "AWS Access Key"},
		{ID: "np.github.1", Name: "GitHub Token"},
	}

	tests := []struct {
		name     string
		config   FilterConfig
		expected int // expected number of rules
	}{
		{
			name:     "empty include and exclude returns all rules",
			config:   FilterConfig{},
			expected: 2,
		},
		{
			name: "empty include slice returns all rules",
			config: FilterConfig{
				Include: []string{},
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered, err := Filter(rules, tt.config)
			require.NoError(t, err)
			assert.Len(t, filtered, tt.expected)
		})
	}
}

func TestFilter_InvalidRegex(t *testing.T) {
	rules := []*types.Rule{
		{ID: "np.aws.1", Name: "AWS Access Key"},
	}

	tests := []struct {
		name    string
		config  FilterConfig
		wantErr bool
	}{
		{
			name: "invalid include regex",
			config: FilterConfig{
				Include: []string{"[invalid"},
			},
			wantErr: true,
		},
		{
			name: "invalid exclude regex",
			config: FilterConfig{
				Exclude: []string{"[invalid"},
			},
			wantErr: true,
		},
		{
			name: "multiple patterns with one invalid",
			config: FilterConfig{
				Include: []string{"np.aws.*", "[invalid"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Filter(rules, tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid regex pattern")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFilter_NilRules(t *testing.T) {
	config := FilterConfig{
		Include: []string{".*"},
	}

	filtered, err := Filter(nil, config)
	require.NoError(t, err)
	assert.Empty(t, filtered)
}
