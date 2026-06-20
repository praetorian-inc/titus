package scoring

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type gcpServiceAccountKey struct {
	ProjectID   string `json:"project_id"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
}

// toJSON reconstructs a minimal service account JSON blob suitable for
// google.CredentialsFromJSON. The type and token_uri fields are required by
// the Google auth library.
func (k *gcpServiceAccountKey) toJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type":         "service_account",
		"project_id":   k.ProjectID,
		"client_email": k.ClientEmail,
		"private_key":  k.PrivateKey,
		"token_uri":    "https://oauth2.googleapis.com/token",
	})
}

type gcpIAMBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

type gcpAncestor struct {
	ResourceID struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"resourceId"`
}

type gcpAPI interface {
	GetProjectIAMPolicy(ctx context.Context, project string) ([]gcpIAMBinding, error)
	GetOrgIAMPolicy(ctx context.Context, project string) ([]gcpIAMBinding, error)
	CountAccessibleProjects(ctx context.Context) (int, error)
}

type gcpClientFactory func(ctx context.Context, key *gcpServiceAccountKey) (gcpAPI, error)

func defaultGCPClientFactory(ctx context.Context, key *gcpServiceAccountKey) (gcpAPI, error) {
	saJSON, err := key.toJSON()
	if err != nil {
		return nil, err
	}
	creds, err := google.CredentialsFromJSON(ctx, saJSON,
		"https://www.googleapis.com/auth/cloud-platform",
	)
	if err != nil {
		return nil, err
	}
	// Force a token exchange to validate the SA is active. A disabled SA
	// returns an error here before any API calls are made.
	tok, err := creds.TokenSource.Token()
	if err != nil {
		return nil, err
	}
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(tok))
	return &gcpHTTPAPI{client: client, projectID: key.ProjectID, clientEmail: key.ClientEmail}, nil
}

type gcpHTTPAPI struct {
	client      *http.Client
	projectID   string
	clientEmail string
}

func (a *gcpHTTPAPI) GetProjectIAMPolicy(ctx context.Context, project string) ([]gcpIAMBinding, error) {
	url := "https://cloudresourcemanager.googleapis.com/v1/projects/" + project + ":getIamPolicy"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getIamPolicy: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Bindings []gcpIAMBinding `json:"bindings"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result.Bindings, nil
}

func (a *gcpHTTPAPI) getOrgID(ctx context.Context, project string) (string, error) {
	url := "https://cloudresourcemanager.googleapis.com/v1/projects/" + project + ":getAncestry"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}

	var result struct {
		Ancestor []gcpAncestor `json:"ancestor"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	for _, a := range result.Ancestor {
		if a.ResourceID.Type == "organization" {
			return a.ResourceID.ID, nil
		}
	}
	return "", nil
}

func (a *gcpHTTPAPI) GetOrgIAMPolicy(ctx context.Context, project string) ([]gcpIAMBinding, error) {
	orgID, err := a.getOrgID(ctx, project)
	if err != nil {
		return nil, err
	}
	if orgID == "" {
		return nil, nil
	}

	url := "https://cloudresourcemanager.googleapis.com/v1/organizations/" + orgID + ":getIamPolicy"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getIamPolicy: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Bindings []gcpIAMBinding `json:"bindings"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result.Bindings, nil
}

func (a *gcpHTTPAPI) CountAccessibleProjects(ctx context.Context) (int, error) {
	// Single page of up to 100 projects — sufficient for the >= 5 threshold.
	url := "https://cloudresourcemanager.googleapis.com/v3/projects?pageSize=100"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("countProjects: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Projects []json.RawMessage `json:"projects"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, err
	}
	return len(result.Projects), nil
}
