package scoring

import (
	"context"
	"fmt"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Credential extraction tests
// ---------------------------------------------------------------------------

func TestExtractMongoCredentialsNP_AllGroupsPresent(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"username": []byte("myuser"),
			"password": []byte("mypass"),
			"host":     []byte("localhost:27017"),
		},
	}
	uri, ok := extractMongoCredentialsNP(m)
	assert.True(t, ok)
	assert.Equal(t, "mongodb://myuser:mypass@localhost:27017", uri)
}

func TestExtractMongoCredentialsNP_MissingGroup_ReturnsFalse(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"username": []byte("myuser"),
			"password": []byte("mypass"),
			// no "host"
		},
	}
	_, ok := extractMongoCredentialsNP(m)
	assert.False(t, ok, "should return false when host is missing")
}

func TestExtractMongoCredentialsNP_NilMatch_ReturnsFalse(t *testing.T) {
	_, ok := extractMongoCredentialsNP(nil)
	assert.False(t, ok)
}

func TestExtractMongoCredentialsKF_FullURI(t *testing.T) {
	m := &types.Match{
		Snippet: types.Snippet{
			Matching: []byte("mongodb+srv://user:pass@cluster0.example.mongodb.net/test"),
		},
	}
	uri, ok := extractMongoCredentialsKF(m)
	assert.True(t, ok)
	assert.Equal(t, "mongodb+srv://user:pass@cluster0.example.mongodb.net/test", uri)
}

func TestExtractMongoCredentialsKF_EmptyMatching_ReturnsFalse(t *testing.T) {
	m := &types.Match{
		Snippet: types.Snippet{
			Matching: []byte(""),
		},
	}
	_, ok := extractMongoCredentialsKF(m)
	assert.False(t, ok)
}

func TestExtractMongoURI_PrefersNPOverKF(t *testing.T) {
	// Match with BOTH named groups AND Snippet.Matching
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"username": []byte("myuser"),
			"password": []byte("mypass"),
			"host":     []byte("localhost:27017"),
		},
		Snippet: types.Snippet{
			Matching: []byte("mongodb+srv://other:creds@cluster.mongodb.net/db"),
		},
	}
	uri, ok := extractMongoURI(m)
	assert.True(t, ok)
	// NP path should win — uri starts with "mongodb://" not "mongodb+srv://"
	assert.True(t, len(uri) > 0 && uri[:10] == "mongodb://", "expected NP path uri, got: %s", uri)
}

// ---------------------------------------------------------------------------
// IsDynamic tests
// ---------------------------------------------------------------------------

func TestMongoRoleCondition_IsDynamic(t *testing.T) {
	cond := &mongoRoleCondition{matchRoles: []string{"root"}}
	mod := Modifier{Condition: cond}
	assert.True(t, mod.IsDynamic())
}

func TestMongoAdminDBCondition_IsDynamic(t *testing.T) {
	cond := &mongoAdminDBCondition{}
	mod := Modifier{Condition: cond}
	assert.True(t, mod.IsDynamic())
}

func TestMongoSensitiveDBCondition_IsDynamic(t *testing.T) {
	cond := &mongoSensitiveDBCondition{pattern: prodPatternMongoDB}
	mod := Modifier{Condition: cond}
	assert.True(t, mod.IsDynamic())
}

func TestMongoReadOnlySingleDBCondition_IsDynamic(t *testing.T) {
	cond := &mongoReadOnlySingleDBCondition{}
	mod := Modifier{Condition: cond}
	assert.True(t, mod.IsDynamic())
}

func TestMongoReadAnyNoWriteCondition_IsDynamic(t *testing.T) {
	cond := &mongoReadAnyNoWriteCondition{}
	mod := Modifier{Condition: cond}
	assert.True(t, mod.IsDynamic())
}

// ---------------------------------------------------------------------------
// Mock implementation
// ---------------------------------------------------------------------------

type mockMongoDBAPI struct {
	status    *MongoConnectionStatus
	statusErr error
	databases []string
	dbErr     error
}

func (m *mockMongoDBAPI) ConnectionStatus(_ context.Context) (*MongoConnectionStatus, error) {
	return m.status, m.statusErr
}

func (m *mockMongoDBAPI) ListDatabases(_ context.Context) ([]string, error) {
	return m.databases, m.dbErr
}

func fakeMongoFactory(api mongoDBAPI) mongoClientFactory {
	return func(_ context.Context, _ string) (mongoDBAPI, func(), error) {
		return api, func() {}, nil
	}
}

func mongoTestMatch() *types.Match {
	return &types.Match{
		NamedGroups: map[string][]byte{
			"username": []byte("testuser"),
			"password": []byte("testpass"),
			"host":     []byte("localhost:27017"),
		},
	}
}

// ---------------------------------------------------------------------------
// mongoRoleCondition tests
// ---------------------------------------------------------------------------

func TestMongoRoleCondition_FiresWhenRootRole(t *testing.T) {
	cond := &mongoRoleCondition{
		matchRoles: []string{"root"},
		clientFactory: fakeMongoFactory(&mockMongoDBAPI{
			status: &MongoConnectionStatus{
				AuthenticatedRoles: []MongoAuthRole{
					{Role: "root", DB: "admin"},
				},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), mongoTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestMongoRoleCondition_DoesNotFireWhenReadOnly(t *testing.T) {
	cond := &mongoRoleCondition{
		matchRoles: []string{"root"},
		clientFactory: fakeMongoFactory(&mockMongoDBAPI{
			status: &MongoConnectionStatus{
				AuthenticatedRoles: []MongoAuthRole{
					{Role: "read", DB: "mydb"},
				},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), mongoTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

// ---------------------------------------------------------------------------
// mongoAdminDBCondition tests
// ---------------------------------------------------------------------------

func TestMongoAdminDBCondition_FiresWhenAdminPresent(t *testing.T) {
	cond := &mongoAdminDBCondition{
		clientFactory: fakeMongoFactory(&mockMongoDBAPI{
			databases: []string{"admin", "mydb"},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), mongoTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestMongoAdminDBCondition_DoesNotFireWhenNoAdmin(t *testing.T) {
	cond := &mongoAdminDBCondition{
		clientFactory: fakeMongoFactory(&mockMongoDBAPI{
			databases: []string{"mydb", "test"},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), mongoTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

// ---------------------------------------------------------------------------
// mongoSensitiveDBCondition tests
// ---------------------------------------------------------------------------

func TestMongoSensitiveDBCondition_FiresForProdDB(t *testing.T) {
	cond := &mongoSensitiveDBCondition{
		pattern: prodPatternMongoDB,
		clientFactory: fakeMongoFactory(&mockMongoDBAPI{
			databases: []string{"production_data", "test"},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), mongoTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestMongoSensitiveDBCondition_DoesNotFireForNonSensitive(t *testing.T) {
	cond := &mongoSensitiveDBCondition{
		pattern: prodPatternMongoDB,
		clientFactory: fakeMongoFactory(&mockMongoDBAPI{
			databases: []string{"test", "development"},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), mongoTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

// ---------------------------------------------------------------------------
// mongoReadOnlySingleDBCondition tests
// ---------------------------------------------------------------------------

func TestMongoReadOnlySingleDBCondition_FiresForSingleReadNonProd(t *testing.T) {
	cond := &mongoReadOnlySingleDBCondition{
		clientFactory: fakeMongoFactory(&mockMongoDBAPI{
			status: &MongoConnectionStatus{
				AuthenticatedRoles: []MongoAuthRole{
					{Role: "read", DB: "analytics"},
				},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), mongoTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestMongoReadOnlySingleDBCondition_DoesNotFireForProdDB(t *testing.T) {
	cond := &mongoReadOnlySingleDBCondition{
		clientFactory: fakeMongoFactory(&mockMongoDBAPI{
			status: &MongoConnectionStatus{
				AuthenticatedRoles: []MongoAuthRole{
					{Role: "read", DB: "production"},
				},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), mongoTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestMongoReadOnlySingleDBCondition_DoesNotFireForMultipleRoles(t *testing.T) {
	cond := &mongoReadOnlySingleDBCondition{
		clientFactory: fakeMongoFactory(&mockMongoDBAPI{
			status: &MongoConnectionStatus{
				AuthenticatedRoles: []MongoAuthRole{
					{Role: "read", DB: "mydb"},
					{Role: "readWrite", DB: "other"},
				},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), mongoTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

// ---------------------------------------------------------------------------
// mongoReadAnyNoWriteCondition tests
// ---------------------------------------------------------------------------

func TestMongoReadAnyNoWriteCondition_FiresForReadAnyOnly(t *testing.T) {
	cond := &mongoReadAnyNoWriteCondition{
		clientFactory: fakeMongoFactory(&mockMongoDBAPI{
			status: &MongoConnectionStatus{
				AuthenticatedRoles: []MongoAuthRole{
					{Role: "readAnyDatabase", DB: "admin"},
					{Role: "read", DB: "test"},
				},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), mongoTestMatch())
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestMongoReadAnyNoWriteCondition_DoesNotFireWhenWriteRolePresent(t *testing.T) {
	cond := &mongoReadAnyNoWriteCondition{
		clientFactory: fakeMongoFactory(&mockMongoDBAPI{
			status: &MongoConnectionStatus{
				AuthenticatedRoles: []MongoAuthRole{
					{Role: "readAnyDatabase", DB: "admin"},
					{Role: "readWrite", DB: "mydb"},
				},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), mongoTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestMongoReadAnyNoWriteCondition_DoesNotFireWithoutReadAny(t *testing.T) {
	cond := &mongoReadAnyNoWriteCondition{
		clientFactory: fakeMongoFactory(&mockMongoDBAPI{
			status: &MongoConnectionStatus{
				AuthenticatedRoles: []MongoAuthRole{
					{Role: "read", DB: "mydb"},
				},
			},
		}),
	}
	fired, err := cond.Evaluate(context.Background(), mongoTestMatch())
	require.NoError(t, err)
	assert.False(t, fired)
}

// ---------------------------------------------------------------------------
// Error handling tests
// ---------------------------------------------------------------------------

func TestMongoRoleCondition_ReturnsFalseOnConnectionError(t *testing.T) {
	// Factory itself returns an error
	errFactory := func(_ context.Context, _ string) (mongoDBAPI, func(), error) {
		return nil, nil, fmt.Errorf("connection refused")
	}
	cond := &mongoRoleCondition{
		matchRoles:    []string{"root"},
		clientFactory: errFactory,
	}
	fired, err := cond.Evaluate(context.Background(), mongoTestMatch())
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestMongoRoleCondition_ReturnsFalseOnStatusError(t *testing.T) {
	cond := &mongoRoleCondition{
		matchRoles: []string{"root"},
		clientFactory: fakeMongoFactory(&mockMongoDBAPI{
			statusErr: fmt.Errorf("auth failed"),
		}),
	}
	fired, err := cond.Evaluate(context.Background(), mongoTestMatch())
	assert.NoError(t, err)
	assert.False(t, fired)
}
