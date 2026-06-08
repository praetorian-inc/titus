package scoring

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// mongoDBAPI is the MongoDB operation subset used by scorers.
type mongoDBAPI interface {
	// ConnectionStatus returns the authenticated user's roles.
	// Equivalent to: db.adminCommand({connectionStatus: 1})
	ConnectionStatus(ctx context.Context) (*MongoConnectionStatus, error)

	// ListDatabases returns accessible database names.
	// Equivalent to: db.adminCommand({listDatabases: 1, nameOnly: true})
	ListDatabases(ctx context.Context) ([]string, error)
}

// MongoConnectionStatus holds the parsed response from connectionStatus.
type MongoConnectionStatus struct {
	AuthenticatedUsers []MongoAuthUser
	AuthenticatedRoles []MongoAuthRole
}

// MongoAuthUser represents a single authenticated user entry.
type MongoAuthUser struct {
	User string
	DB   string
}

// MongoAuthRole represents a single authenticated role entry.
type MongoAuthRole struct {
	Role string
	DB   string
}

// mongoClientFactory creates a MongoDB client from a connection URI.
// Inject a fake factory in tests; the default uses the real mongo-driver.
type mongoClientFactory func(ctx context.Context, uri string) (mongoDBAPI, func(), error)

// mongoDriverClient wraps a *mongo.Client and implements mongoDBAPI.
type mongoDriverClient struct {
	client *mongo.Client
}

func (c *mongoDriverClient) ConnectionStatus(ctx context.Context) (*MongoConnectionStatus, error) {
	raw, err := c.client.Database("admin").RunCommand(ctx, bson.D{{Key: "connectionStatus", Value: 1}}).Raw()
	if err != nil {
		return nil, err
	}

	var out MongoConnectionStatus

	if usersVal, err := raw.LookupErr("authInfo", "authenticatedUsers"); err == nil {
		elems, err := bson.Raw(usersVal.Array()).Elements()
		if err == nil {
			for _, elem := range elems {
				var u struct {
					User string `bson:"user"`
					DB   string `bson:"db"`
				}
				if decErr := bson.Unmarshal(elem.Value().Document(), &u); decErr == nil {
					out.AuthenticatedUsers = append(out.AuthenticatedUsers, MongoAuthUser{User: u.User, DB: u.DB})
				}
			}
		}
	}

	if rolesVal, err := raw.LookupErr("authInfo", "authenticatedRoles"); err == nil {
		elems, err := bson.Raw(rolesVal.Array()).Elements()
		if err == nil {
			for _, elem := range elems {
				var r struct {
					Role string `bson:"role"`
					DB   string `bson:"db"`
				}
				if decErr := bson.Unmarshal(elem.Value().Document(), &r); decErr == nil {
					out.AuthenticatedRoles = append(out.AuthenticatedRoles, MongoAuthRole{Role: r.Role, DB: r.DB})
				}
			}
		}
	}

	return &out, nil
}

func (c *mongoDriverClient) ListDatabases(ctx context.Context) ([]string, error) {
	return c.client.ListDatabaseNames(ctx, bson.D{})
}

func defaultMongoClientFactory(ctx context.Context, uri string) (mongoDBAPI, func(), error) {
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		_ = client.Disconnect(context.Background())
	}
	return &mongoDriverClient{client: client}, cleanup, nil
}
