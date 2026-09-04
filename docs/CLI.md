<!-- Generated from the live cobra command tree by 'make cli-docs'. Do not edit by hand. -->

# titus CLI reference

Every command, alias and flag below is derived from the cobra command tree, not from prose.
Schema version 1, surface hash `sha256:0acd16ad62c2775b57bf1cfa8f508594ef49decc0b9f93dcae62aa0f9cc06fa8`.

Regenerate with `make cli-docs` after adding, removing or renaming a command or a flag.

## Command index

| Command | Aliases | Description |
| --- | --- | --- |
| [`titus`](#titus) | *(none)* | Titus - Go port of NoseyParker secrets scanner |
| [`titus confluence`](#titus-confluence) | *(none)* | (deprecated: use 'titus enum confluence' instead) |
| [`titus enum`](#titus-enum) | *(none)* | Enumerate remote services for secrets |
| [`titus enum confluence`](#titus-enum-confluence) | *(none)* | Scan a Confluence instance for secrets |
| [`titus enum discord`](#titus-enum-discord) | *(none)* | Scan Discord servers for secrets |
| [`titus enum gdrive`](#titus-enum-gdrive) | *(none)* | Scan Google Drive for secrets |
| [`titus enum github`](#titus-enum-github) | *(none)* | Scan GitHub repositories for secrets |
| [`titus enum github scan`](#titus-enum-github-scan) | *(none)* | Scan GitHub repository or organization |
| [`titus enum gitlab`](#titus-enum-gitlab) | *(none)* | Scan GitLab projects |
| [`titus enum gitlab scan`](#titus-enum-gitlab-scan) | *(none)* | Scan GitLab project or group |
| [`titus enum jira`](#titus-enum-jira) | *(none)* | Scan a Jira instance for secrets |
| [`titus enum linear`](#titus-enum-linear) | *(none)* | Scan a Linear workspace for secrets |
| [`titus enum microsoft`](#titus-enum-microsoft) | *(none)* | Scan Microsoft 365 services for secrets |
| [`titus enum microsoft sharepoint`](#titus-enum-microsoft-sharepoint) | *(none)* | Scan SharePoint sites for secrets |
| [`titus enum notion`](#titus-enum-notion) | *(none)* | Scan a Notion workspace for secrets |
| [`titus enum servicenow`](#titus-enum-servicenow) | *(none)* | Scan a ServiceNow instance for secrets |
| [`titus enum slack`](#titus-enum-slack) | *(none)* | Scan a Slack workspace for secrets |
| [`titus enum trello`](#titus-enum-trello) | *(none)* | Scan Trello boards for secrets |
| [`titus enum zendesk`](#titus-enum-zendesk) | *(none)* | Scan a Zendesk instance for secrets |
| [`titus explore`](#titus-explore) | *(none)* | Interactively explore scan results |
| [`titus github`](#titus-github) | *(none)* | (deprecated: use 'titus enum github' instead) |
| [`titus github scan`](#titus-github-scan) | *(none)* | (deprecated: use 'titus enum github scan' instead) |
| [`titus gitlab`](#titus-gitlab) | *(none)* | (deprecated: use 'titus enum gitlab' instead) |
| [`titus gitlab scan`](#titus-gitlab-scan) | *(none)* | (deprecated: use 'titus enum gitlab scan' instead) |
| [`titus jira`](#titus-jira) | *(none)* | (deprecated: use 'titus enum jira' instead) |
| [`titus linear`](#titus-linear) | *(none)* | (deprecated: use 'titus enum linear' instead) |
| [`titus notion`](#titus-notion) | *(none)* | (deprecated: use 'titus enum notion' instead) |
| [`titus report`](#titus-report) | *(none)* | Generate a report from scan results |
| [`titus report summary`](#titus-report-summary) | *(none)* | Show a summary of findings by rule type |
| [`titus rules`](#titus-rules) | *(none)* | Manage detection rules |
| [`titus rules list`](#titus-rules-list) | *(none)* | List available rules |
| [`titus scan`](#titus-scan) | *(none)* | Scan a target for secrets |
| [`titus serve`](#titus-serve) | *(none)* | Run as streaming server for Burp extension integration |
| [`titus sharepoint`](#titus-sharepoint) | *(none)* | (deprecated: use 'titus enum microsoft sharepoint' instead) |
| [`titus slack`](#titus-slack) | *(none)* | (deprecated: use 'titus enum slack' instead) |
| [`titus version`](#titus-version) | *(none)* | Show version information |

## `titus`

Titus - Go port of NoseyParker secrets scanner

- Usage: `titus`
- Aliases: *(none)*
- Requires a subcommand

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus confluence`

- Usage: `titus confluence`
- Aliases: *(none)*
- Hidden: not shown in `--help` output
- Deprecated: use 'titus enum confluence' instead

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--base-url` |  | string |  | Confluence base URL (or CONFLUENCE_BASE_URL env) |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--rate-limit` |  | float64 | `5` | Requests per second |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--spaces` |  | string |  | Comma-separated space keys to scan (empty = all) |
| `--token` |  | string |  | Confluence API token or PAT (or CONFLUENCE_TOKEN env) |
| `--username` |  | string |  | Confluence username for Cloud basic auth (or CONFLUENCE_USERNAME env) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum`

Enumerate remote services for secrets

- Usage: `titus enum`
- Aliases: *(none)*
- Requires a subcommand

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum confluence`

Scan a Confluence instance for secrets

- Usage: `titus enum confluence`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--base-url` |  | string |  | Confluence base URL (or CONFLUENCE_BASE_URL env) |
| `--rate-limit` |  | float64 | `5` | Requests per second |
| `--spaces` |  | string |  | Comma-separated space keys to scan (empty = all) |
| `--token` |  | string |  | Confluence API token or PAT (or CONFLUENCE_TOKEN env) |
| `--username` |  | string |  | Confluence username for Cloud basic auth (or CONFLUENCE_USERNAME env) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum discord`

Scan Discord servers for secrets

- Usage: `titus enum discord`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--channels` |  | string |  | Comma-separated channel IDs to scan (default: all text channels) |
| `--guilds` |  | string |  | Comma-separated guild/server IDs to scan (default: all) |
| `--rate-limit` |  | float64 | `2` | Requests per second |
| `--token` |  | string |  | Discord Bot token (or DISCORD_TOKEN env) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum gdrive`

Scan Google Drive for secrets

- Usage: `titus enum gdrive`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--client-id` |  | string |  | OAuth client ID (or GOOGLE_DRIVE_CLIENT_ID env) |
| `--client-secret` |  | string |  | OAuth client secret (or GOOGLE_DRIVE_CLIENT_SECRET env) |
| `--concurrency` |  | int | `5` | Number of parallel file download workers |
| `--drive-id` |  | string |  | Scan a single shared drive by ID |
| `--extract` |  | string | `xlsx` | Extract text from binary files (extensions: xlsx,docx,pdf,zip or 'all') |
| `--max-file-size` |  | int64 | `10485760` | Maximum file size to scan in bytes (0 = unlimited) |
| `--rate-limit` |  | float64 | `16` | Requests per second |
| `--refresh-token` |  | string |  | OAuth refresh token (or GOOGLE_DRIVE_REFRESH_TOKEN env) |
| `--scope` |  | string | `all` | Drive scope: all, mine, shared-with-me, shared-drives |
| `--token` |  | string |  | OAuth access token (or GOOGLE_DRIVE_TOKEN env) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum github`

Scan GitHub repositories for secrets

- Usage: `titus enum github [owner/repo]`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--git` |  | bool | `false` | Scan full git history (slower; default scans only current files) |
| `--jitter` |  | float64 | `0` | Maximum random delay in seconds between repository clones (e.g., 1200 for 20min; combined with --rate-limit as minimum) |
| `--no-clone` |  | bool | `false` | Fetch files via API instead of cloning (requires token, no git history) |
| `--org` |  | string |  | Scan all repositories in organization |
| `--rate-limit` |  | float64 | `0` | Delay in seconds between repository clones (e.g., 2 or 0.5; 0 = no delay) |
| `--skip-forks` |  | bool | `false` | Skip forked repositories when scanning orgs or users |
| `--token` |  | string |  | GitHub API token (or GITHUB_TOKEN env; optional for public repos) |
| `--url` |  | string |  | GitHub Enterprise base URL (or GITHUB_BASE_URL env; e.g., https://github.example.com) |
| `--user` |  | string |  | Scan all repositories for user |
| `--yes` | `-y` | bool | `false` | Skip confirmation prompt for scan time estimate |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum github scan`

Scan GitHub repository or organization

- Usage: `titus enum github scan [owner/repo]`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--git` |  | bool | `false` | Scan full git history (slower; default scans only current files) |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--jitter` |  | float64 | `0` | Maximum random delay in seconds between repository clones (e.g., 1200 for 20min; combined with --rate-limit as minimum) |
| `--no-clone` |  | bool | `false` | Fetch files via API instead of cloning (requires token, no git history) |
| `--org` |  | string |  | Scan all repositories in organization |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--rate-limit` |  | float64 | `0` | Delay in seconds between repository clones (e.g., 2 or 0.5; 0 = no delay) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--skip-forks` |  | bool | `false` | Skip forked repositories when scanning orgs or users |
| `--token` |  | string |  | GitHub API token (or GITHUB_TOKEN env; optional for public repos) |
| `--url` |  | string |  | GitHub Enterprise base URL (or GITHUB_BASE_URL env; e.g., https://github.example.com) |
| `--user` |  | string |  | Scan all repositories for user |
| `--yes` | `-y` | bool | `false` | Skip confirmation prompt for scan time estimate |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum gitlab`

Scan GitLab projects

- Usage: `titus enum gitlab [namespace/project]`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--git` |  | bool | `false` | Scan full git history (slower; default scans only current files) |
| `--group` |  | string |  | Scan all projects in group |
| `--jitter` |  | float64 | `0` | Maximum random delay in seconds between project clones (e.g., 1200 for 20min; combined with --rate-limit as minimum) |
| `--no-clone` |  | bool | `false` | Fetch files via API instead of cloning (requires token, no git history) |
| `--rate-limit` |  | float64 | `0` | Delay in seconds between project clones (e.g., 2 or 0.5; 0 = no delay) |
| `--token` |  | string |  | GitLab token (or GITLAB_TOKEN env; optional for public projects) |
| `--url` |  | string |  | GitLab base URL (default: gitlab.com) |
| `--user` |  | string |  | Scan all projects for user |
| `--yes` | `-y` | bool | `false` | Skip confirmation prompt for scan time estimate |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum gitlab scan`

Scan GitLab project or group

- Usage: `titus enum gitlab scan [namespace/project]`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--git` |  | bool | `false` | Scan full git history (slower; default scans only current files) |
| `--group` |  | string |  | Scan all projects in group |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--jitter` |  | float64 | `0` | Maximum random delay in seconds between project clones (e.g., 1200 for 20min; combined with --rate-limit as minimum) |
| `--no-clone` |  | bool | `false` | Fetch files via API instead of cloning (requires token, no git history) |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--rate-limit` |  | float64 | `0` | Delay in seconds between project clones (e.g., 2 or 0.5; 0 = no delay) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--token` |  | string |  | GitLab token (or GITLAB_TOKEN env; optional for public projects) |
| `--url` |  | string |  | GitLab base URL (default: gitlab.com) |
| `--user` |  | string |  | Scan all projects for user |
| `--yes` | `-y` | bool | `false` | Skip confirmation prompt for scan time estimate |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum jira`

Scan a Jira instance for secrets

- Usage: `titus enum jira`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--allow-insecure` |  | bool | `false` | Allow plaintext HTTP base URLs (for internal instances) |
| `--base-url` |  | string |  | Jira base URL (or JIRA_BASE_URL env) |
| `--projects` |  | string |  | Comma-separated project keys to scan (empty = all) |
| `--rate-limit` |  | float64 | `5` | Requests per second |
| `--token` |  | string |  | Jira API token or PAT (or JIRA_TOKEN env) |
| `--username` |  | string |  | Jira username for Cloud basic auth (or JIRA_USERNAME env) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum linear`

Scan a Linear workspace for secrets

- Usage: `titus enum linear`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--token` |  | string |  | Linear API key (or LINEAR_TOKEN env) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum microsoft`

Scan Microsoft 365 services for secrets

- Usage: `titus enum microsoft`
- Aliases: *(none)*
- Requires a subcommand

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--client-id` |  | string | `1950a258-227b-4e31-a9cf-717495945fc2` | Azure AD application (client) ID for device code auth |
| `--refresh-token` |  | string |  | Microsoft refresh token (or SHAREPOINT_REFRESH_TOKEN env) |
| `--tenant-id` |  | string | `organizations` | Azure AD tenant ID (or 'organizations') |
| `--token` |  | string |  | Graph API OAuth bearer token (or SHAREPOINT_TOKEN env) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum microsoft sharepoint`

Scan SharePoint sites for secrets

- Usage: `titus enum microsoft sharepoint`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--site` |  | string |  | Specific site URL or name to scan (empty = all sites) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--client-id` |  | string | `1950a258-227b-4e31-a9cf-717495945fc2` | Azure AD application (client) ID for device code auth |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--refresh-token` |  | string |  | Microsoft refresh token (or SHAREPOINT_REFRESH_TOKEN env) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--tenant-id` |  | string | `organizations` | Azure AD tenant ID (or 'organizations') |
| `--token` |  | string |  | Graph API OAuth bearer token (or SHAREPOINT_TOKEN env) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum notion`

Scan a Notion workspace for secrets

- Usage: `titus enum notion`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `10` | Number of parallel page fetchers |
| `--page` |  | string |  | Scan a single page (URL or page ID) |
| `--teamspace` |  | string |  | Scan only pages in this teamspace (name or ID) |
| `--token` |  | string |  | Notion token_v2 session cookie (or NOTION_TOKEN env) |
| `--workspace` |  | string |  | Workspace name or ID (for multi-workspace accounts) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum servicenow`

Scan a ServiceNow instance for secrets

- Usage: `titus enum servicenow`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--allow-insecure-http` |  | bool | `false` | Allow plaintext HTTP instance URLs |
| `--instance` |  | string |  | ServiceNow instance URL (or SERVICENOW_INSTANCE env) |
| `--oauth-token` |  | string |  | ServiceNow OAuth2 bearer token (or SERVICENOW_OAUTH_TOKEN env) |
| `--password` |  | string |  | ServiceNow password for basic auth (or SERVICENOW_PASSWORD env) |
| `--rate-limit` |  | float64 | `3` | Requests per second |
| `--tables` |  | string |  | Comma-separated table names to scan (default: incident,change_request,kb_knowledge) |
| `--username` |  | string |  | ServiceNow username for basic auth (or SERVICENOW_USERNAME env) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum slack`

Scan a Slack workspace for secrets

- Usage: `titus enum slack`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--channels` |  | string |  | Comma-separated channel names to scan (default: all) |
| `--cookie` |  | string |  | Slack session cookie (xoxd-...) — required for xoxc- tokens (or SLACK_COOKIE env) |
| `--rate-limit` |  | float64 | `0.75` | API requests per second (default 0.75, Slack Tier 3 = 50 req/min) |
| `--token` |  | string |  | Slack API token (or SLACK_TOKEN env) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum trello`

Scan Trello boards for secrets

- Usage: `titus enum trello`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--api-key` |  | string |  | Trello API key (or TRELLO_API_KEY env) |
| `--boards` |  | string |  | Comma-separated board IDs to scan (default: all) |
| `--rate-limit` |  | float64 | `3` | Requests per second |
| `--token` |  | string |  | Trello user token (or TRELLO_TOKEN env) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus enum zendesk`

Scan a Zendesk instance for secrets

- Usage: `titus enum zendesk`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--email` |  | string |  | Agent email address (or ZENDESK_EMAIL env) |
| `--rate-limit` |  | float64 | `3` | Requests per second |
| `--subdomain` |  | string |  | Zendesk subdomain (or ZENDESK_SUBDOMAIN env) |
| `--token` |  | string |  | Zendesk API token (or ZENDESK_TOKEN env) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus explore`

Interactively explore scan results

- Usage: `titus explore [datastore]`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--datastore` |  | string | `titus.ds` | Path to datastore directory or file |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus github`

- Usage: `titus github`
- Aliases: *(none)*
- Hidden: not shown in `--help` output
- Deprecated: use 'titus enum github' instead

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--git` |  | bool | `false` | Scan full git history (slower; default scans only current files) |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--jitter` |  | float64 | `0` | Maximum random delay in seconds between repository clones (e.g., 1200 for 20min; combined with --rate-limit as minimum) |
| `--no-clone` |  | bool | `false` | Fetch files via API instead of cloning (requires token, no git history) |
| `--org` |  | string |  | Scan all repositories in organization |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--rate-limit` |  | float64 | `0` | Delay in seconds between repository clones (e.g., 2 or 0.5; 0 = no delay) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--skip-forks` |  | bool | `false` | Skip forked repositories when scanning orgs or users |
| `--token` |  | string |  | GitHub API token (or GITHUB_TOKEN env; optional for public repos) |
| `--url` |  | string |  | GitHub Enterprise base URL (or GITHUB_BASE_URL env; e.g., https://github.example.com) |
| `--user` |  | string |  | Scan all repositories for user |
| `--yes` | `-y` | bool | `false` | Skip confirmation prompt for scan time estimate |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus github scan`

- Usage: `titus github scan`
- Aliases: *(none)*
- Hidden: not shown in `--help` output
- Deprecated: use 'titus enum github scan' instead

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--git` |  | bool | `false` | Scan full git history (slower; default scans only current files) |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--jitter` |  | float64 | `0` | Maximum random delay in seconds between repository clones (e.g., 1200 for 20min; combined with --rate-limit as minimum) |
| `--no-clone` |  | bool | `false` | Fetch files via API instead of cloning (requires token, no git history) |
| `--org` |  | string |  | Scan all repositories in organization |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--rate-limit` |  | float64 | `0` | Delay in seconds between repository clones (e.g., 2 or 0.5; 0 = no delay) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--skip-forks` |  | bool | `false` | Skip forked repositories when scanning orgs or users |
| `--token` |  | string |  | GitHub API token (or GITHUB_TOKEN env; optional for public repos) |
| `--url` |  | string |  | GitHub Enterprise base URL (or GITHUB_BASE_URL env; e.g., https://github.example.com) |
| `--user` |  | string |  | Scan all repositories for user |
| `--yes` | `-y` | bool | `false` | Skip confirmation prompt for scan time estimate |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus gitlab`

- Usage: `titus gitlab`
- Aliases: *(none)*
- Hidden: not shown in `--help` output
- Deprecated: use 'titus enum gitlab' instead

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--git` |  | bool | `false` | Scan full git history (slower; default scans only current files) |
| `--group` |  | string |  | Scan all projects in group |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--jitter` |  | float64 | `0` | Maximum random delay in seconds between project clones (e.g., 1200 for 20min; combined with --rate-limit as minimum) |
| `--no-clone` |  | bool | `false` | Fetch files via API instead of cloning (requires token, no git history) |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--rate-limit` |  | float64 | `0` | Delay in seconds between project clones (e.g., 2 or 0.5; 0 = no delay) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--token` |  | string |  | GitLab token (or GITLAB_TOKEN env; optional for public projects) |
| `--url` |  | string |  | GitLab base URL (default: gitlab.com) |
| `--user` |  | string |  | Scan all projects for user |
| `--yes` | `-y` | bool | `false` | Skip confirmation prompt for scan time estimate |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus gitlab scan`

- Usage: `titus gitlab scan`
- Aliases: *(none)*
- Hidden: not shown in `--help` output
- Deprecated: use 'titus enum gitlab scan' instead

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--git` |  | bool | `false` | Scan full git history (slower; default scans only current files) |
| `--group` |  | string |  | Scan all projects in group |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--jitter` |  | float64 | `0` | Maximum random delay in seconds between project clones (e.g., 1200 for 20min; combined with --rate-limit as minimum) |
| `--no-clone` |  | bool | `false` | Fetch files via API instead of cloning (requires token, no git history) |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--rate-limit` |  | float64 | `0` | Delay in seconds between project clones (e.g., 2 or 0.5; 0 = no delay) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--token` |  | string |  | GitLab token (or GITLAB_TOKEN env; optional for public projects) |
| `--url` |  | string |  | GitLab base URL (default: gitlab.com) |
| `--user` |  | string |  | Scan all projects for user |
| `--yes` | `-y` | bool | `false` | Skip confirmation prompt for scan time estimate |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus jira`

- Usage: `titus jira`
- Aliases: *(none)*
- Hidden: not shown in `--help` output
- Deprecated: use 'titus enum jira' instead

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--allow-insecure` |  | bool | `false` | Allow plaintext HTTP base URLs (for internal instances) |
| `--base-url` |  | string |  | Jira base URL (or JIRA_BASE_URL env) |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--projects` |  | string |  | Comma-separated project keys to scan (empty = all) |
| `--rate-limit` |  | float64 | `5` | Requests per second |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--token` |  | string |  | Jira API token or PAT (or JIRA_TOKEN env) |
| `--username` |  | string |  | Jira username for Cloud basic auth (or JIRA_USERNAME env) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus linear`

- Usage: `titus linear`
- Aliases: *(none)*
- Hidden: not shown in `--help` output
- Deprecated: use 'titus enum linear' instead

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--token` |  | string |  | Linear API key (or LINEAR_TOKEN env) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus notion`

- Usage: `titus notion`
- Aliases: *(none)*
- Hidden: not shown in `--help` output
- Deprecated: use 'titus enum notion' instead

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `10` | Number of parallel page fetchers |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--page` |  | string |  | Scan a single page (URL or page ID) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--teamspace` |  | string |  | Scan only pages in this teamspace (name or ID) |
| `--token` |  | string |  | Notion token_v2 session cookie (or NOTION_TOKEN env) |
| `--workspace` |  | string |  | Workspace name or ID (for multi-workspace accounts) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus report`

Generate a report from scan results

- Usage: `titus report`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--color` |  | string | `auto` | Color output: auto, always, never |
| `--datastore` |  | string | `titus.ds` | Path to datastore directory or file |
| `--format` |  | string | `human` | Output format: human, json, sarif |
| `--show-rejected` |  | bool | `false` | Include findings marked as rejected via the explore command (hidden by default) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus report summary`

Show a summary of findings by rule type

- Usage: `titus report summary`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `human` | Output format: human, json |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--color` |  | string | `auto` | Color output: auto, always, never |
| `--datastore` |  | string | `titus.ds` | Path to datastore directory or file |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--show-rejected` |  | bool | `false` | Include findings marked as rejected via the explore command (hidden by default) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus rules`

Manage detection rules

- Usage: `titus rules`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus rules list`

List available rules

- Usage: `titus rules list`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--format` |  | string | `table` | Output format: table, json |
| `--include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--include-noisy` |  | bool | `false` | Include rules marked noisy: true (off by default; high false-positive rate) |
| `--rules` |  | string |  | Path to custom rules file or directory |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus scan`

Scan a target for secrets

- Usage: `titus scan <target>`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--accessibility` |  | string | `auto` | code accessibility: "public" (no penalty), "private" (-25 to all scores), or "auto" (detect via git remote/GitHub API, defaults to private if undetermined) |
| `--asana-attachment-max-size` |  | int64 | `52428800` | Maximum Asana attachment size in bytes to download |
| `--asana-concurrency` |  | int | `0` | Number of workers processing tasks within a project (0 = use default of 5) |
| `--asana-include-attachments` |  | bool | `false` | Download and scan Asana-hosted file attachments |
| `--asana-rate-limit` |  | float64 | `10` | Asana API requests per second (free tier ≈ 2.5/sec; paid tier ≈ 25/sec) |
| `--context-lines` |  | int | `3` | Lines of context before/after matches (0 to disable) |
| `--docker` |  | bool | `false` | Treat target as Docker image (uses docker image save) |
| `--extract` |  | extensions |  | Extract text from binary files (extensions: xlsx,docx,pdf,zip or 'all') |
| `--extract-max-depth` |  | int | `5` | Max nested archive depth |
| `--extract-max-size` |  | string | `10MB` | Max uncompressed size per extracted file |
| `--extract-max-total` |  | string | `100MB` | Max total bytes to extract from one archive |
| `--format` |  | string | `human` | Output format: json, sarif, human |
| `--gdrive-concurrency` |  | int | `0` | Google Drive parallel file workers (default 5; 0 = use default; clamped to [1, 100]) |
| `--gdrive-rate-limit` |  | float64 | `0` | Google Drive API requests per second (default 16; 0 = use default). Per-user cap is ~325k quota units/min |
| `--git` |  | bool | `false` | Treat target as git repository (enumerate git history) |
| `--ignore` |  | string |  | Path to gitignore-style ignore file (replaces built-in defaults; use /dev/null to disable) |
| `--include-noisy` |  | bool | `false` | Enable rules marked noisy: true (off by default; high false-positive rate) |
| `--incremental` |  | bool | `false` | Skip already-scanned blobs |
| `--max-file-size` |  | int64 | `10485760` | Maximum file size to scan (bytes) |
| `--output` |  | string | `titus.ds` | Output datastore path (:memory: for in-memory, :auto: to derive from target name) |
| `--readers` |  | int | `0` | Number of parallel file readers (0 = NumCPU) |
| `--rules` |  | string |  | Path to custom rules file or directory |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all (all = no filtering) |
| `--score-budget` |  | duration | `1m0s` | per-finding overall scoring budget across all modifiers (default 60s; 0 = unlimited) |
| `--score-scope` |  | bool | `false` | enable HTTP dynamic scoring modifiers (calls external APIs to determine secret scope/permissions) |
| `--score-timeout` |  | duration | `10s` | per-modifier HTTP timeout for dynamic scoring (default 10s) |
| `--sqlite-row-limit` |  | int | `1000` | Max rows per table for SQLite extraction (0 for unlimited) |
| `--store-blobs` |  | bool | `false` | Store file contents in blobs/ directory |
| `--validate` |  | bool | `false` | validate detected secrets against their source APIs |
| `--validate-workers` |  | int | `4` | number of concurrent validation workers |
| `--workers` |  | int | `18` | Number of parallel scan workers |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus serve`

Run as streaming server for Burp extension integration

- Usage: `titus serve`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--include-noisy` |  | bool | `true` | Enable rules marked noisy: true (high false-positive rate) |
| `--rules` |  | string |  | Path to custom rules file or directory |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `all` | Ruleset to use: default, np.assets, np.hashes, all (all = no filtering) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus sharepoint`

- Usage: `titus sharepoint`
- Aliases: *(none)*
- Hidden: not shown in `--help` output
- Deprecated: use 'titus enum microsoft sharepoint' instead

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--client-id` |  | string | `1950a258-227b-4e31-a9cf-717495945fc2` | Azure AD application (client) ID for device code auth |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--refresh-token` |  | string |  | Microsoft refresh token (or SHAREPOINT_REFRESH_TOKEN env) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--site` |  | string |  | Specific site URL or name to scan (empty = all sites) |
| `--tenant-id` |  | string | `organizations` | Azure AD tenant ID (or 'organizations') |
| `--token` |  | string |  | Graph API OAuth bearer token (or SHAREPOINT_TOKEN env) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus slack`

- Usage: `titus slack`
- Aliases: *(none)*
- Hidden: not shown in `--help` output
- Deprecated: use 'titus enum slack' instead

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--channels` |  | string |  | Comma-separated channel names to scan (default: all) |
| `--cookie` |  | string |  | Slack session cookie (xoxd-...) — required for xoxc- tokens (or SLACK_COOKIE env) |
| `--format` |  | string | `human` | Output format: json, human |
| `--include-noisy` |  | bool | `false` | Include noisy rules that may produce more false positives |
| `--output` |  | string | `titus.db` | Output database path (:memory: for in-memory, :auto: to derive from target name) |
| `--rate-limit` |  | float64 | `0.75` | API requests per second (default 0.75, Slack Tier 3 = 50 req/min) |
| `--rules` |  | string |  | Path to custom rules file or directory (merged with builtins) |
| `--rules-exclude` |  | string |  | Exclude rules matching regex pattern (comma-separated) |
| `--rules-include` |  | string |  | Include rules matching regex pattern (comma-separated) |
| `--ruleset` |  | string | `default` | Ruleset to use: default, np.assets, np.hashes, all |
| `--token` |  | string |  | Slack API token (or SLACK_TOKEN env) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |

## `titus version`

Show version information

- Usage: `titus version`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--quiet` | `-q` | bool | `false` | Quiet mode (errors only) |
| `--verbose` | `-v` | bool | `false` | Verbose output |
