package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/praetorian-inc/titus/pkg/auth"
	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
)

var (
	sharepointToken      string
	spRefreshToken       string
	sharepointSite       string
	sharepointOutputPath string
	sharepointFormat     string
	spClientID           string
	spTenantID           string
)

var sharepointCmd = &cobra.Command{
	Use:   "sharepoint",
	Short: "Scan SharePoint sites for secrets",
	Long: `Scan SharePoint sites for secrets via the Microsoft Graph API.

Authentication:
  Use --token with an OAuth bearer token that has Sites.Read.All permission,
  or omit --token to use the interactive device code flow.

  Use --refresh-token with a Microsoft refresh token to skip the device code flow.
  Get a refresh token from GraphRunner, TokenTacticsV2, roadtx, or a previous
  Titus authentication cached at ~/.titus/microsoft_token.json.

Examples:
  titus sharepoint -v                                          # device code flow (interactive)
  titus sharepoint --token <bearer_token> -v                   # direct token
  titus sharepoint --token <bearer_token> --site https://company.sharepoint.com/sites/Engineering
  titus sharepoint --client-id 14d82eec-204b-4c2f-b7e8-296a70dab67e -v  # alternate client ID
  titus sharepoint --refresh-token <refresh_token> -v              # use refresh token (no browser needed)
  SHAREPOINT_REFRESH_TOKEN=<token> titus sharepoint -v             # via env var`,
	RunE: runSharePointScan,
}

func init() {
	sharepointCmd.Flags().StringVar(&sharepointToken, "token", "", "Graph API OAuth bearer token (or SHAREPOINT_TOKEN env)")
	sharepointCmd.Flags().StringVar(&sharepointSite, "site", "", "Specific site URL or name to scan (empty = all sites)")
	sharepointCmd.Flags().StringVar(&sharepointOutputPath, "output", "titus.db", "Output database path")
	sharepointCmd.Flags().StringVar(&sharepointFormat, "format", "human", "Output format: json, human")
	sharepointCmd.Flags().StringVar(&spClientID, "client-id", auth.AzurePowerShellClientID, "Azure AD application (client) ID for device code auth")
	sharepointCmd.Flags().StringVar(&spTenantID, "tenant-id", auth.DefaultTenantID, "Azure AD tenant ID (or 'organizations' for multi-tenant)")
	sharepointCmd.Flags().StringVar(&spRefreshToken, "refresh-token", "", "Microsoft refresh token to exchange for access token (or SHAREPOINT_REFRESH_TOKEN env)")
	sharepointCmd.Flags().StringVar(&scanRulesPath, "rules", "", "Path to custom rules file or directory (merged with builtins)")
	sharepointCmd.Flags().StringVar(&scanRulesInclude, "rules-include", "", "Include rules matching regex pattern (comma-separated)")
	sharepointCmd.Flags().StringVar(&scanRulesExclude, "rules-exclude", "", "Exclude rules matching regex pattern (comma-separated)")
	sharepointCmd.Flags().StringVar(&scanRuleset, "ruleset", "default", "Ruleset to use: default, np.assets, np.hashes, all")
	sharepointCmd.Flags().BoolVar(&scanIncludeNoisy, "include-noisy", false, "Include noisy rules that may produce more false positives")
}

func runSharePointScan(cmd *cobra.Command, args []string) error {
	token := sharepointToken
	if token == "" {
		token = os.Getenv("SHAREPOINT_TOKEN")
	}

	if token == "" {
		refreshToken := spRefreshToken
		if refreshToken == "" {
			refreshToken = os.Getenv("SHAREPOINT_REFRESH_TOKEN")
		}

		scopes := []string{"https://graph.microsoft.com/Sites.Read.All", "https://graph.microsoft.com/Files.Read.All", "offline_access"}

		if refreshToken != "" {
			// Option 1: Explicit refresh token provided.
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Exchanging refresh token for access token...")
			result, err := auth.RefreshToken(cmd.Context(), spClientID, spTenantID, refreshToken, scopes)
			if err != nil {
				return fmt.Errorf("refresh token exchange failed: %w", err)
			}
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Authentication successful.")
			token = result.AccessToken
			// Save for future runs.
			_ = auth.SaveCachedToken(result, spClientID, spTenantID)
		} else {
			// Option 2: Try cached token first.
			cached, err := auth.LoadCachedToken()
			if err == nil && cached.ClientID == spClientID && cached.TenantID == spTenantID {
				if time.Now().Add(5 * time.Minute).Before(cached.ExpiresAt) {
					// Cached token still valid.
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Using cached token (expires %s)\n", cached.ExpiresAt.Format("15:04:05"))
					token = cached.AccessToken
				} else if cached.RefreshToken != "" {
					// Cached token expired, refresh it.
					_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Refreshing cached token...")
					result, err := auth.RefreshToken(cmd.Context(), spClientID, spTenantID, cached.RefreshToken, scopes)
					if err == nil {
						token = result.AccessToken
						_ = auth.SaveCachedToken(result, spClientID, spTenantID)
						_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Token refreshed successfully.")
					} else {
						_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: cached token refresh failed (%v); falling back to device code flow.\n", err)
					}
				}
			}

			if token == "" {
				// Option 3: Interactive device code flow.
				result, err := auth.DeviceCodeAuth(cmd.Context(), spClientID, spTenantID, scopes, cmd.ErrOrStderr())
				if err != nil {
					return fmt.Errorf("device code authentication failed: %w", err)
				}
				token = result.AccessToken
				// Save for future runs.
				_ = auth.SaveCachedToken(result, spClientID, spTenantID)
				if result.RefreshToken != "" {
					_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Token cached at ~/.titus/microsoft_token.json")
				}
			}
		}
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewSharePointEnumerator(enum.SharePointConfig{
		Token:   token,
		Site:    sharepointSite,
		Verbose: verboseWriter,
	})
	if err != nil {
		return fmt.Errorf("creating SharePoint enumerator: %w", err)
	}

	rules, err := loadRules(scanRulesPath, scanRulesInclude, scanRulesExclude, scanRuleset, scanIncludeNoisy)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	m, err := matcher.New(matcher.Config{
		Rules:        rules,
		ContextLines: 3,
	})
	if err != nil {
		return fmt.Errorf("creating matcher: %w", err)
	}
	defer m.Close()

	s, err := store.New(store.Config{
		Path: sharepointOutputPath,
	})
	if err != nil {
		return fmt.Errorf("creating store: %w", err)
	}
	defer s.Close()

	for _, r := range rules {
		if err := s.AddRule(r); err != nil {
			return fmt.Errorf("storing rule: %w", err)
		}
	}

	ctx := cmd.Context()
	matchCount := 0
	findingCount := 0

	err = enumerator.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		if err := s.AddBlob(blobID, int64(len(content))); err != nil {
			return fmt.Errorf("storing blob: %w", err)
		}

		if err := s.AddProvenance(blobID, prov); err != nil {
			return fmt.Errorf("storing provenance: %w", err)
		}

		matches, err := m.MatchWithBlobID(content, blobID)
		if err != nil {
			return fmt.Errorf("matching content: %w", err)
		}

		for _, match := range matches {
			startLine, startCol := types.ComputeLineColumn(content, int(match.Location.Offset.Start))
			endLine, endCol := types.ComputeLineColumn(content, int(match.Location.Offset.End))
			match.Location.Source.Start.Line = startLine
			match.Location.Source.Start.Column = startCol
			match.Location.Source.End.Line = endLine
			match.Location.Source.End.Column = endCol
		}

		for _, match := range matches {
			matchCount++

			if err := s.AddMatch(match); err != nil {
				return fmt.Errorf("storing match: %w", err)
			}

			rule, ok := ruleMap[match.RuleID]
			if !ok {
				return fmt.Errorf("rule not found: %s", match.RuleID)
			}
			findingID := types.ComputeFindingID(rule.StructuralID, match.Groups)
			exists, err := s.FindingExists(findingID)
			if err != nil {
				return fmt.Errorf("checking finding: %w", err)
			}

			if !exists {
				findingCount++
				finding := &types.Finding{
					ID:     findingID,
					RuleID: match.RuleID,
					Groups: match.Groups,
				}
				if err := s.AddFinding(finding); err != nil {
					return fmt.Errorf("storing finding: %w", err)
				}
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("scanning SharePoint: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "SharePoint scan complete: %d matches, %d findings\n", matchCount, findingCount)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Results stored in: %s\n", sharepointOutputPath)

	if sharepointFormat == "json" {
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputMatches(cmd, matches)
	}

	findings, err := s.GetFindings()
	if err != nil {
		return fmt.Errorf("retrieving findings: %w", err)
	}
	return outputFindings(cmd, findings)
}
