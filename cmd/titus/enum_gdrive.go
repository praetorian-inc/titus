package main

import (
	"fmt"
	"io"
	"os"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	gdriveToken        string
	gdriveRefreshToken string
	gdriveClientID     string
	gdriveClientSecret string
	gdriveScope        string
	gdriveDriveID      string
	gdriveRateLimit    float64
	gdriveConcurrency  int
)

var gdriveCmd = &cobra.Command{
	Use:   "gdrive",
	Short: "Scan Google Drive for secrets",
	Long: `Scan Google Drive files for secrets via the Drive API v3.
Enumerates Google Docs, Sheets, Slides, and uploaded files.

Authentication:
  Use an OAuth access token, or a refresh token with client credentials for
  automatic token renewal on long scans.

  --token or GOOGLE_DRIVE_TOKEN: short-lived OAuth access token.
  --refresh-token + --client-id + --client-secret: auto-refreshing credentials.

Scope:
  --scope controls which slice of Drive to enumerate:
    all             My Drive + shared-with-me + all shared drives (default)
    mine            Only files in My Drive
    shared-with-me  Only files shared with the authenticated user
    shared-drives   All shared drives (no My Drive or shared-with-me)

  --drive-id scans a single shared drive by ID.

Examples:
  GOOGLE_DRIVE_TOKEN=ya29.xxx titus enum gdrive
  titus enum gdrive --token ya29.xxx --scope mine
  titus enum gdrive --token ya29.xxx --drive-id 0ABcd1EfGhIjKl
  titus enum gdrive --refresh-token 1//xxx --client-id CID --client-secret CS --scope shared-drives`,
	RunE: runGDriveEnumScan,
}

func registerGDriveFlags(fs *pflag.FlagSet) {
	fs.StringVar(&gdriveToken, "token", "", "OAuth access token (or GOOGLE_DRIVE_TOKEN env)")
	fs.StringVar(&gdriveRefreshToken, "refresh-token", "", "OAuth refresh token (or GOOGLE_DRIVE_REFRESH_TOKEN env)")
	fs.StringVar(&gdriveClientID, "client-id", "", "OAuth client ID (or GOOGLE_DRIVE_CLIENT_ID env)")
	fs.StringVar(&gdriveClientSecret, "client-secret", "", "OAuth client secret (or GOOGLE_DRIVE_CLIENT_SECRET env)")
	fs.StringVar(&gdriveScope, "scope", "all", "Drive scope: all, mine, shared-with-me, shared-drives")
	fs.StringVar(&gdriveDriveID, "drive-id", "", "Scan a single shared drive by ID")
	fs.Float64Var(&gdriveRateLimit, "rate-limit", 16, "Requests per second")
	fs.IntVar(&gdriveConcurrency, "concurrency", 5, "Number of parallel file download workers")
}

func init() {
	registerGDriveFlags(gdriveCmd.Flags())
}

func runGDriveEnumScan(cmd *cobra.Command, args []string) error {
	token := envOrFlag(gdriveToken, "GOOGLE_DRIVE_TOKEN")
	refresh := envOrFlag(gdriveRefreshToken, "GOOGLE_DRIVE_REFRESH_TOKEN")
	clientID := envOrFlag(gdriveClientID, "GOOGLE_DRIVE_CLIENT_ID")
	clientSecret := envOrFlag(gdriveClientSecret, "GOOGLE_DRIVE_CLIENT_SECRET")

	if token == "" && refresh == "" {
		return fmt.Errorf("auth required: set --token / GOOGLE_DRIVE_TOKEN, or --refresh-token + --client-id + --client-secret")
	}

	scope, err := parseGDriveScope(gdriveScope, gdriveDriveID)
	if err != nil {
		return err
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewGDriveEnumerator(enum.GDriveConfig{
		Token:        token,
		RefreshToken: refresh,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        scope,
		DriveID:      gdriveDriveID,
		Verbose:      verboseWriter,
		RateLimit:    gdriveRateLimit,
		Concurrency:  gdriveConcurrency,
	})
	if err != nil {
		return fmt.Errorf("creating Google Drive enumerator: %w", err)
	}

	return runEnumScan(cmd, enumerator, "Google Drive")
}

func parseGDriveScope(scopeStr, driveID string) (enum.GDriveScope, error) {
	if driveID != "" {
		return enum.GDriveScopeSingleDrive, nil
	}
	switch scopeStr {
	case "all":
		return enum.GDriveScopeAll, nil
	case "mine":
		return enum.GDriveScopeMine, nil
	case "shared-with-me":
		return enum.GDriveScopeSharedWithMe, nil
	case "shared-drives":
		return enum.GDriveScopeSharedDrives, nil
	default:
		return 0, fmt.Errorf("unknown --scope %q (expected all, mine, shared-with-me, shared-drives)", scopeStr)
	}
}

func envOrFlag(flag, envVar string) string {
	if flag != "" {
		return flag
	}
	return os.Getenv(envVar)
}
