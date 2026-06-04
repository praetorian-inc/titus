// pkg/validator/pubnub_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

const testSubKey = "sub-c-test0000-exam-ple0-fake-000000000000"
const testPubKey = "pub-c-test0000-exam-ple0-fake-000000000000"

func TestPubNubValidator_Name(t *testing.T) {
	v := NewPubNubValidator()
	assert.Equal(t, "pubnub", v.Name())
}

func TestPubNubValidator_CanValidate(t *testing.T) {
	v := NewPubNubValidator()
	assert.True(t, v.CanValidate("kingfisher.pubnub.1"))
	assert.True(t, v.CanValidate("kingfisher.pubnub.2"))
	assert.False(t, v.CanValidate("np.github.1"))
}

func TestPubNubValidator_SubKey_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, testSubKey)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewPubNubValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "kingfisher.pubnub.2",
		Groups: [][]byte{[]byte(testSubKey)},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestPubNubValidator_SubKey_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	v := NewPubNubValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "kingfisher.pubnub.2",
		Groups: [][]byte{[]byte(testSubKey)},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestPubNubValidator_SubKey_MissingGroup(t *testing.T) {
	v := NewPubNubValidator()

	match := &types.Match{
		RuleID: "kingfisher.pubnub.2",
		Groups: [][]byte{},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
}

func TestPubNubValidator_PubKey_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, testPubKey)
		assert.Contains(t, r.URL.Path, testSubKey)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewPubNubValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "kingfisher.pubnub.1",
		Groups: [][]byte{[]byte(testPubKey)},
		Snippet: types.Snippet{
			Before: []byte("sub_key = '" + testSubKey + "'\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestPubNubValidator_PubKey_MissingSubKey(t *testing.T) {
	v := NewPubNubValidator()

	match := &types.Match{
		RuleID: "kingfisher.pubnub.1",
		Groups: [][]byte{[]byte(testPubKey)},
		Snippet: types.Snippet{
			Before: []byte("no sub key here\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "subscription key not in context")
}

func TestPubNubValidator_PubKey_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	v := NewPubNubValidatorWithClient(&http.Client{
		Transport: &testTransport{url: server.URL},
	})

	match := &types.Match{
		RuleID: "kingfisher.pubnub.1",
		Groups: [][]byte{[]byte(testPubKey)},
		Snippet: types.Snippet{
			After: []byte("SUBSCRIBE_KEY=" + testSubKey + "\n"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestExtractPositionalGroup_FromGroups(t *testing.T) {
	m := &types.Match{Groups: [][]byte{[]byte("test-value")}}
	assert.Equal(t, "test-value", extractPositionalGroup(m))
}

func TestExtractPositionalGroup_FromNamedGroup(t *testing.T) {
	m := &types.Match{
		Groups:      [][]byte{},
		NamedGroups: map[string][]byte{"token": []byte("test-value")},
	}
	assert.Equal(t, "test-value", extractPositionalGroup(m))
}

func TestExtractPositionalGroup_Empty(t *testing.T) {
	m := &types.Match{Groups: [][]byte{}, NamedGroups: map[string][]byte{}}
	assert.Equal(t, "", extractPositionalGroup(m))
}
