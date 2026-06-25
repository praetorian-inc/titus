package main

import (
	"github.com/praetorian-inc/titus/pkg/auth"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	msToken        string
	msRefreshToken string
	msClientID     string
	msTenantID     string
)

var microsoftCmd = &cobra.Command{
	Use:   "microsoft",
	Short: "Scan Microsoft 365 services for secrets",
	Long: `Scan Microsoft 365 services (SharePoint, OneDrive, Teams) for secrets
via the Microsoft Graph API.`,
}

// registerMicrosoftFlags registers the shared Microsoft auth flags on the given FlagSet.
func registerMicrosoftFlags(fs *pflag.FlagSet) {
	fs.StringVar(&msToken, "token", "", "Graph API OAuth bearer token (or SHAREPOINT_TOKEN env)")
	fs.StringVar(&msRefreshToken, "refresh-token", "", "Microsoft refresh token (or SHAREPOINT_REFRESH_TOKEN env)")
	fs.StringVar(&msClientID, "client-id", auth.AzurePowerShellClientID, "Azure AD application (client) ID for device code auth")
	fs.StringVar(&msTenantID, "tenant-id", auth.DefaultTenantID, "Azure AD tenant ID (or 'organizations')")
}

func init() {
	registerMicrosoftFlags(microsoftCmd.PersistentFlags())
	microsoftCmd.AddCommand(sharepointCmd)
}
