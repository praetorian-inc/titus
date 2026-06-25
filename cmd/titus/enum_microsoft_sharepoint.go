package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/praetorian-inc/titus/pkg/auth"
	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var sharepointSite string

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
  titus enum microsoft sharepoint -v                                          # device code flow (interactive)
  titus enum microsoft sharepoint --token <bearer_token> -v                   # direct token
  titus enum microsoft sharepoint --token <bearer_token> --site https://company.sharepoint.com/sites/Engineering
  titus enum microsoft sharepoint --client-id 14d82eec-204b-4c2f-b7e8-296a70dab67e -v  # alternate client ID
  titus enum microsoft sharepoint --refresh-token <refresh_token> -v              # use refresh token (no browser needed)
  SHAREPOINT_REFRESH_TOKEN=<token> titus enum microsoft sharepoint -v             # via env var`,
	RunE: runSharePointScan,
}

// registerSharePointFlags registers SharePoint-specific flags on the given FlagSet.
func registerSharePointFlags(fs *pflag.FlagSet) {
	fs.StringVar(&sharepointSite, "site", "", "Specific site URL or name to scan (empty = all sites)")
}

func init() {
	registerSharePointFlags(sharepointCmd.Flags())
}

func runSharePointScan(cmd *cobra.Command, args []string) error {
	// Auth reads from the microsoft parent's persistent globals (msToken, msRefreshToken, msClientID, msTenantID).
	token := msToken
	if token == "" {
		token = os.Getenv("SHAREPOINT_TOKEN")
	}

	if token == "" {
		refreshToken := msRefreshToken
		if refreshToken == "" {
			refreshToken = os.Getenv("SHAREPOINT_REFRESH_TOKEN")
		}

		scopes := []string{"https://graph.microsoft.com/Sites.Read.All", "https://graph.microsoft.com/Files.Read.All", "offline_access"}

		if refreshToken != "" {
			// Option 1: Explicit refresh token provided.
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Exchanging refresh token for access token...")
			result, err := auth.RefreshToken(cmd.Context(), msClientID, msTenantID, refreshToken, scopes)
			if err != nil {
				return fmt.Errorf("refresh token exchange failed: %w", err)
			}
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Authentication successful.")
			token = result.AccessToken
			// Save for future runs.
			_ = auth.SaveCachedToken(result, msClientID, msTenantID)
		} else {
			// Option 2: Try cached token first.
			cached, err := auth.LoadCachedToken()
			if err == nil && cached.ClientID == msClientID && cached.TenantID == msTenantID {
				if time.Now().Add(5 * time.Minute).Before(cached.ExpiresAt) {
					// Cached token still valid.
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Using cached token (expires %s)\n", cached.ExpiresAt.Format("15:04:05"))
					token = cached.AccessToken
				} else if cached.RefreshToken != "" {
					// Cached token expired, refresh it.
					_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Refreshing cached token...")
					result, err := auth.RefreshToken(cmd.Context(), msClientID, msTenantID, cached.RefreshToken, scopes)
					if err == nil {
						token = result.AccessToken
						_ = auth.SaveCachedToken(result, msClientID, msTenantID)
						_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Token refreshed successfully.")
					} else {
						_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: cached token refresh failed (%v); falling back to device code flow.\n", err)
					}
				}
			}

			if token == "" {
				// Option 3: Interactive device code flow.
				result, err := auth.DeviceCodeAuth(cmd.Context(), msClientID, msTenantID, scopes, cmd.ErrOrStderr())
				if err != nil {
					return fmt.Errorf("device code authentication failed: %w", err)
				}
				token = result.AccessToken
				// Save for future runs.
				_ = auth.SaveCachedToken(result, msClientID, msTenantID)
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

	return runEnumScan(cmd, enumerator, "SharePoint")
}
