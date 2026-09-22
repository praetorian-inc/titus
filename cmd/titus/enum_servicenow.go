package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	servicenowInstance          string
	servicenowUsername          string
	servicenowPassword          string
	servicenowOAuthToken        string
	servicenowTables            string
	servicenowRateLimit         float64
	servicenowAllowInsecureHTTP bool
)

var servicenowCmd = &cobra.Command{
	Use:   "servicenow",
	Short: "Scan a ServiceNow instance for secrets",
	Long: `Scan a ServiceNow instance for secrets via the REST Table API.
Enumerates records from configurable tables (default: incident, change_request, kb_knowledge).

Authentication:
  Basic auth: use --username and --password.
  OAuth: use --oauth-token with a bearer token.

Examples:
  titus enum servicenow --instance https://mycompany.service-now.com --username admin --password s3cret
  SERVICENOW_INSTANCE=https://mycompany.service-now.com SERVICENOW_OAUTH_TOKEN=tok titus enum servicenow
  titus enum servicenow --instance https://mycompany.service-now.com --username admin --password s3cret --tables incident,kb_knowledge,sc_req_item`,
	RunE: runServiceNowEnumScan,
}

func registerServiceNowFlags(fs *pflag.FlagSet) {
	fs.StringVar(&servicenowInstance, "instance", "", "ServiceNow instance URL (or SERVICENOW_INSTANCE env)")
	fs.StringVar(&servicenowUsername, "username", "", "ServiceNow username for basic auth (or SERVICENOW_USERNAME env)")
	fs.StringVar(&servicenowPassword, "password", "", "ServiceNow password for basic auth (or SERVICENOW_PASSWORD env)")
	fs.StringVar(&servicenowOAuthToken, "oauth-token", "", "ServiceNow OAuth2 bearer token (or SERVICENOW_OAUTH_TOKEN env)")
	fs.StringVar(&servicenowTables, "tables", "", "Comma-separated table names to scan (default: incident,change_request,kb_knowledge)")
	fs.Float64Var(&servicenowRateLimit, "rate-limit", 3.0, "Requests per second")
	fs.BoolVar(&servicenowAllowInsecureHTTP, "allow-insecure-http", false, "Allow plaintext HTTP instance URLs")
}

func init() {
	registerServiceNowFlags(servicenowCmd.Flags())
}

func runServiceNowEnumScan(cmd *cobra.Command, args []string) error {
	instance := servicenowInstance
	if instance == "" {
		instance = os.Getenv("SERVICENOW_INSTANCE")
	}
	if instance == "" {
		return fmt.Errorf("servicenow instance URL is required: use --instance or SERVICENOW_INSTANCE env var")
	}

	username := servicenowUsername
	if username == "" {
		username = os.Getenv("SERVICENOW_USERNAME")
	}

	password := servicenowPassword
	if password == "" {
		password = os.Getenv("SERVICENOW_PASSWORD")
	}

	oauthToken := servicenowOAuthToken
	if oauthToken == "" {
		oauthToken = os.Getenv("SERVICENOW_OAUTH_TOKEN")
	}

	var tables []string
	if servicenowTables != "" {
		for _, t := range strings.Split(servicenowTables, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tables = append(tables, t)
			}
		}
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewServiceNowEnumerator(enum.ServiceNowConfig{
		Instance:          instance,
		Username:          username,
		Password:          password,
		OAuthToken:        oauthToken,
		Tables:            tables,
		RateLimit:         servicenowRateLimit,
		AllowInsecureHTTP: servicenowAllowInsecureHTTP,
		Verbose:           verboseWriter,
	})
	if err != nil {
		return fmt.Errorf("creating ServiceNow enumerator: %w", err)
	}

	return runEnumScan(cmd, enumerator, "ServiceNow")
}
