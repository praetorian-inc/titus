package rule

import (
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestMicrosoftTeamsWebhook_RuleExists verifies the np.msteams.1 rule exists
// and has the correct structure
func TestMicrosoftTeamsWebhook_RuleExists(t *testing.T) {
	// Load the microsoft_teams.yml file
	data, err := builtinRulesFS.ReadFile("rules/microsoft_teams.yml")
	require.NoError(t, err, "Failed to read microsoft_teams.yml")

	// Parse the YAML to get all rules
	var yamlFile yamlRulesFile
	err = yaml.Unmarshal(data, &yamlFile)
	require.NoError(t, err, "Failed to parse microsoft_teams.yml")

	// Find the np.msteams.1 rule
	var msTeamsRule *yamlRule
	for i := range yamlFile.Rules {
		if yamlFile.Rules[i].ID == "np.msteams.1" {
			msTeamsRule = &yamlFile.Rules[i]
			break
		}
	}

	require.NotNil(t, msTeamsRule, "np.msteams.1 rule not found in microsoft_teams.yml")

	// Verify the rule has the expected properties
	assert.Equal(t, "Microsoft Teams Webhook", msTeamsRule.Name)

	// Verify pattern contains key components
	pattern := msTeamsRule.Pattern
	assert.Contains(t, pattern, "(?P<webhook>", "Pattern should have named capture group 'webhook'")
	assert.Contains(t, pattern, "outlook\\.office\\.com/webhook/", "Pattern should match outlook.office.com/webhook")
	assert.Contains(t, pattern, "IncomingWebhook", "Pattern should contain IncomingWebhook path segment")

	// Verify categories
	assert.Contains(t, msTeamsRule.Categories, "api", "Rule should have 'api' category")
	assert.Contains(t, msTeamsRule.Categories, "secret", "Rule should have 'secret' category")

	// Verify examples exist
	assert.NotEmpty(t, msTeamsRule.Examples, "Rule should have at least one example")

	// Verify negative examples exist
	assert.NotEmpty(t, msTeamsRule.NegativeExamples, "Rule should have at least one negative example")

	// Verify references exist
	assert.NotEmpty(t, msTeamsRule.References, "Rule should have at least one reference")
}

// TestMicrosoftTeamsWebhook_PatternMatches tests that positive examples match
func TestMicrosoftTeamsWebhook_PatternMatches(t *testing.T) {
	// Load the microsoft_teams.yml file
	data, err := builtinRulesFS.ReadFile("rules/microsoft_teams.yml")
	require.NoError(t, err, "Failed to read microsoft_teams.yml")

	// Parse the YAML
	var yamlFile yamlRulesFile
	err = yaml.Unmarshal(data, &yamlFile)
	require.NoError(t, err, "Failed to parse microsoft_teams.yml")

	// Find the np.msteams.1 rule
	var msTeamsRule *yamlRule
	for i := range yamlFile.Rules {
		if yamlFile.Rules[i].ID == "np.msteams.1" {
			msTeamsRule = &yamlFile.Rules[i]
			break
		}
	}
	require.NotNil(t, msTeamsRule, "np.msteams.1 rule not found")

	// Compile the pattern with standard Go regexp (supports (?P<name>) named groups)
	// Note: Go's regexp doesn't support (?x) extended mode, so we need to strip whitespace
	pattern := strings.ReplaceAll(msTeamsRule.Pattern, "\n", "")
	pattern = regexp.MustCompile(`\s+`).ReplaceAllString(pattern, "")
	// Remove (?x) and (?i) flags as Go regexp uses different syntax
	pattern = strings.ReplaceAll(pattern, "(?x)(?i)", "")

	re, err := regexp.Compile("(?i)" + pattern)
	require.NoError(t, err, "Pattern should compile without error")

	// Test cases from YAML examples
	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		{
			name:        "Example 1 from YAML",
			input:       "//test //url = 'https://outlook.office.com/webhook/9da5da9c-4218-4c22-aed6-b5c8baebfff5@2f2b54b7-0141-4ba7-8fcd-ab7d17a60547/IncomingWebhook/1bf66ccbb8e745e791fa6e6de0cf465b/4361420b-8fde-48eb-b62a-0e34fec63f5c';",
			shouldMatch: true,
		},
		{
			name:        "Example 2 from YAML",
			input:       "    [T2`https://outlook.office.com/webhook/fa4983ab-49ea-4c1b-9297-2658ea56164c@f784fbed-7fc7-4c7a-aae9-d2f387b67c5d/IncomingWebhook/4d2b3a16113d47b080b7a083b5a5e533/74f315eb-1dde-4731-b6b5-2524b77f2acd`]",
			shouldMatch: true,
		},
		{
			name:        "Example 3 from YAML (curl context)",
			input:       `curl -H "Content-Type: application/json" -d "{\"text\": \"Debut du script deploy.sh \"}" https://outlook.office.com/webhook/555aa7fc-ea71-4fb7-ae9e-755caa4404ed@72f988bf-86f1-41af-91ab-2d7cd011db47/IncomingWebhook/16085df23e564bb9076842605ede3af2/51dab674-ad95-4f0a-8964-8bdefc25b6d9`,
			shouldMatch: true,
		},
		{
			name:        "Example 4 from YAML (webhooks: prefix)",
			input:       "  webhooks: https://outlook.office.com/webhook/2f92c502-7feb-4a6c-86f1-477271ae576f@990414fa-d0a3-42f5-b740-21d865a44a28/IncomingWebhook/54e43eb586f14aa9984d5c0bec3d5050/539ce6fa-e9aa-413f-a79b-fb7e8998fcac",
			shouldMatch: true,
		},
		{
			name:        "Negative example - JenkinsCI URL",
			input:       "			office365ConnectorSend message: 'Execucao Concluida.', status: 'End', webhookUrl: 'https://outlook.office.com/webhook/82fc2788-c6f4-4507-a657-36c91eccfd87@93f33571-550f-43cf-b09f-cd33c338d086/JenkinsCI/4f3bbf41e81a4f36887a1a4d7cbfb2c6/82fa2788-c6f4-45c7-a657-36f91eccfd87'",
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matched := re.MatchString(tc.input)

			if tc.shouldMatch {
				assert.True(t, matched, "Expected pattern to match input")
			} else {
				assert.False(t, matched, "Expected pattern NOT to match input")
			}
		})
	}
}

// TestMicrosoftTeamsWebhook_NamedCaptureGroup verifies the webhook capture group extracts full URL
func TestMicrosoftTeamsWebhook_NamedCaptureGroup(t *testing.T) {
	// Load the microsoft_teams.yml file
	data, err := builtinRulesFS.ReadFile("rules/microsoft_teams.yml")
	require.NoError(t, err, "Failed to read microsoft_teams.yml")

	// Parse the YAML
	var yamlFile yamlRulesFile
	err = yaml.Unmarshal(data, &yamlFile)
	require.NoError(t, err, "Failed to parse microsoft_teams.yml")

	// Find the np.msteams.1 rule
	var msTeamsRule *yamlRule
	for i := range yamlFile.Rules {
		if yamlFile.Rules[i].ID == "np.msteams.1" {
			msTeamsRule = &yamlFile.Rules[i]
			break
		}
	}
	require.NotNil(t, msTeamsRule, "np.msteams.1 rule not found")

	// Compile the pattern (clean it for Go regexp)
	pattern := strings.ReplaceAll(msTeamsRule.Pattern, "\n", "")
	pattern = regexp.MustCompile(`\s+`).ReplaceAllString(pattern, "")
	pattern = strings.ReplaceAll(pattern, "(?x)(?i)", "")

	re, err := regexp.Compile("(?i)" + pattern)
	require.NoError(t, err, "Pattern should compile without error")

	// Test with a full example
	input := `curl https://outlook.office.com/webhook/555aa7fc-ea71-4fb7-ae9e-755caa4404ed@72f988bf-86f1-41af-91ab-2d7cd011db47/IncomingWebhook/16085df23e564bb9076842605ede3af2/51dab674-ad95-4f0a-8964-8bdefc25b6d9`

	match := re.FindStringSubmatch(input)
	require.NotEmpty(t, match, "Pattern should match input")

	// Get named capture groups
	names := re.SubexpNames()
	namedGroups := make(map[string]string)
	for i, name := range names {
		if name != "" && i < len(match) {
			namedGroups[name] = match[i]
		}
	}

	capturedURL, ok := namedGroups["webhook"]
	require.True(t, ok, "Named capture group 'webhook' should exist")
	require.NotEmpty(t, capturedURL, "Captured webhook should not be empty")

	// Verify captured value is a complete URL
	assert.True(t, strings.HasPrefix(capturedURL, "https://"), "Captured value should start with https://")
	assert.Contains(t, capturedURL, "outlook.office.com/webhook/", "Captured value should contain outlook.office.com/webhook/")
	assert.Contains(t, capturedURL, "/IncomingWebhook/", "Captured value should contain /IncomingWebhook/")

	// Verify it's a valid URL
	parsedURL, err := url.Parse(capturedURL)
	assert.NoError(t, err, "Captured value should be a valid URL")
	assert.Equal(t, "https", parsedURL.Scheme, "URL scheme should be https")
	assert.Equal(t, "outlook.office.com", parsedURL.Host, "URL host should be outlook.office.com")
}

// TestKingfisherMicrosoftTeamsWebhook_RuleExists verifies the kingfisher.microsoftteamswebhook.1 rule exists
func TestKingfisherMicrosoftTeamsWebhook_RuleExists(t *testing.T) {
	// Load the microsoftteamswebhook.yml file
	data, err := builtinRulesFS.ReadFile("rules/microsoftteamswebhook.yml")
	require.NoError(t, err, "Failed to read microsoftteamswebhook.yml")

	// Parse the YAML
	var yamlFile yamlRulesFile
	err = yaml.Unmarshal(data, &yamlFile)
	require.NoError(t, err, "Failed to parse microsoftteamswebhook.yml")

	// Find the kingfisher.microsoftteamswebhook.1 rule
	var kingfisherRule *yamlRule
	for i := range yamlFile.Rules {
		if yamlFile.Rules[i].ID == "kingfisher.microsoftteamswebhook.1" {
			kingfisherRule = &yamlFile.Rules[i]
			break
		}
	}

	require.NotNil(t, kingfisherRule, "kingfisher.microsoftteamswebhook.1 rule not found")

	// Verify the rule has the expected properties
	assert.Equal(t, "Microsoft Teams Webhook", kingfisherRule.Name)

	// Verify pattern contains key components
	pattern := kingfisherRule.Pattern
	assert.Contains(t, pattern, "(?P<webhook>", "Pattern should have named capture group 'webhook'")
	assert.Contains(t, pattern, "webhook\\.office\\.com/webhookb2", "Pattern should match webhook.office.com/webhookb2")
	assert.Contains(t, pattern, "IncomingWebhook", "Pattern should contain IncomingWebhook path segment")

	// Verify examples exist
	assert.NotEmpty(t, kingfisherRule.Examples, "Rule should have at least one example")
}

// TestKingfisherMicrosoftTeamsWebhook_PatternMatches tests pattern matching for kingfisher rule
func TestKingfisherMicrosoftTeamsWebhook_PatternMatches(t *testing.T) {
	// Load the microsoftteamswebhook.yml file
	data, err := builtinRulesFS.ReadFile("rules/microsoftteamswebhook.yml")
	require.NoError(t, err, "Failed to read microsoftteamswebhook.yml")

	// Parse the YAML
	var yamlFile yamlRulesFile
	err = yaml.Unmarshal(data, &yamlFile)
	require.NoError(t, err, "Failed to parse microsoftteamswebhook.yml")

	// Find the kingfisher.microsoftteamswebhook.1 rule
	var kingfisherRule *yamlRule
	for i := range yamlFile.Rules {
		if yamlFile.Rules[i].ID == "kingfisher.microsoftteamswebhook.1" {
			kingfisherRule = &yamlFile.Rules[i]
			break
		}
	}
	require.NotNil(t, kingfisherRule, "kingfisher.microsoftteamswebhook.1 rule not found")

	// Compile the pattern (clean it for Go regexp)
	pattern := strings.ReplaceAll(kingfisherRule.Pattern, "\n", "")
	pattern = regexp.MustCompile(`\s+`).ReplaceAllString(pattern, "")
	pattern = strings.ReplaceAll(pattern, "(?xi)", "")

	re, err := regexp.Compile("(?i)" + pattern)
	require.NoError(t, err, "Pattern should compile without error")

	// Test cases
	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		{
			name:        "Example from YAML (contoso.webhook.office.com)",
			input:       "https://contoso.webhook.office.com/webhookb2/12345678-abcd-1234-efgh-56789abcdef0@12345678-abcd-1234-efgh-56789abcdef0/IncomingWebhook/abcdefgh12345678abcdefgh12345678/12345678-abcd-1234-efgh-56789abcdef0",
			shouldMatch: true,
		},
		{
			name:        "Different subdomain",
			input:       "https://mycompany.webhook.office.com/webhookb2/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@ffffffff-0000-1111-2222-333333333333/IncomingWebhook/01234567890123456789012345678901/44444444-5555-6666-7777-888888888888",
			shouldMatch: true,
		},
		{
			name:        "Legacy outlook.office.com format (should NOT match)",
			input:       "https://outlook.office.com/webhook/9da5da9c-4218-4c22-aed6-b5c8baebfff5@2f2b54b7-0141-4ba7-8fcd-ab7d17a60547/IncomingWebhook/1bf66ccbb8e745e791fa6e6de0cf465b/4361420b-8fde-48eb-b62a-0e34fec63f5c",
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matched := re.MatchString(tc.input)

			if tc.shouldMatch {
				assert.True(t, matched, "Expected pattern to match input")
			} else {
				assert.False(t, matched, "Expected pattern NOT to match input")
			}
		})
	}
}

// TestKingfisherMicrosoftTeamsWebhook_NamedCaptureGroup verifies webhook capture group extracts full URL
func TestKingfisherMicrosoftTeamsWebhook_NamedCaptureGroup(t *testing.T) {
	// Load the microsoftteamswebhook.yml file
	data, err := builtinRulesFS.ReadFile("rules/microsoftteamswebhook.yml")
	require.NoError(t, err, "Failed to read microsoftteamswebhook.yml")

	// Parse the YAML
	var yamlFile yamlRulesFile
	err = yaml.Unmarshal(data, &yamlFile)
	require.NoError(t, err, "Failed to parse microsoftteamswebhook.yml")

	// Find the kingfisher.microsoftteamswebhook.1 rule
	var kingfisherRule *yamlRule
	for i := range yamlFile.Rules {
		if yamlFile.Rules[i].ID == "kingfisher.microsoftteamswebhook.1" {
			kingfisherRule = &yamlFile.Rules[i]
			break
		}
	}
	require.NotNil(t, kingfisherRule, "kingfisher.microsoftteamswebhook.1 rule not found")

	// Compile the pattern (clean it for Go regexp)
	pattern := strings.ReplaceAll(kingfisherRule.Pattern, "\n", "")
	pattern = regexp.MustCompile(`\s+`).ReplaceAllString(pattern, "")
	pattern = strings.ReplaceAll(pattern, "(?xi)", "")

	re, err := regexp.Compile("(?i)" + pattern)
	require.NoError(t, err, "Pattern should compile without error")

	// Test with the example
	input := "https://contoso.webhook.office.com/webhookb2/12345678-abcd-1234-efgh-56789abcdef0@12345678-abcd-1234-efgh-56789abcdef0/IncomingWebhook/abcdefgh12345678abcdefgh12345678/12345678-abcd-1234-efgh-56789abcdef0"

	match := re.FindStringSubmatch(input)
	require.NotEmpty(t, match, "Pattern should match input")

	// Get named capture groups
	names := re.SubexpNames()
	namedGroups := make(map[string]string)
	for i, name := range names {
		if name != "" && i < len(match) {
			namedGroups[name] = match[i]
		}
	}

	capturedURL, ok := namedGroups["webhook"]
	require.True(t, ok, "Named capture group 'webhook' should exist")
	require.NotEmpty(t, capturedURL, "Captured webhook should not be empty")

	// Verify captured value is a complete URL
	assert.True(t, strings.HasPrefix(capturedURL, "https://"), "Captured value should start with https://")
	assert.Contains(t, capturedURL, ".webhook.office.com/webhookb2", "Captured value should contain .webhook.office.com/webhookb2")
	assert.Contains(t, capturedURL, "/IncomingWebhook/", "Captured value should contain /IncomingWebhook/")

	// Verify it's a valid URL
	parsedURL, err := url.Parse(capturedURL)
	assert.NoError(t, err, "Captured value should be a valid URL")
	assert.Equal(t, "https", parsedURL.Scheme, "URL scheme should be https")
	assert.True(t, strings.HasSuffix(parsedURL.Host, ".webhook.office.com"), "URL host should end with .webhook.office.com")
}

// TestMicrosoftTeamsWebhook_ValidationBlock verifies validation YAML structure for np.msteams.1
func TestMicrosoftTeamsWebhook_ValidationBlock(t *testing.T) {
	// Load the microsoft_teams.yml file
	data, err := builtinRulesFS.ReadFile("rules/microsoft_teams.yml")
	require.NoError(t, err, "Failed to read microsoft_teams.yml")

	// Parse the raw YAML to access validation structure
	var yamlFile map[string]interface{}
	err = yaml.Unmarshal(data, &yamlFile)
	require.NoError(t, err, "Failed to parse microsoft_teams.yml")

	rules, ok := yamlFile["rules"].([]interface{})
	require.True(t, ok, "YAML should have 'rules' array")
	require.NotEmpty(t, rules, "Rules array should not be empty")

	// Get the first rule (np.msteams.1)
	rule, ok := rules[0].(map[string]interface{})
	require.True(t, ok, "Rule should be a map")

	// Verify validation block exists
	validation, ok := rule["validation"].(map[string]interface{})
	require.True(t, ok, "Rule should have validation block")

	// Verify validation type
	validationType, ok := validation["type"].(string)
	require.True(t, ok, "Validation should have type field")
	assert.Equal(t, "Http", validationType, "Validation type should be Http")

	// Verify content exists
	content, ok := validation["content"].(map[string]interface{})
	require.True(t, ok, "Validation should have content block")

	// Verify request block
	request, ok := content["request"].(map[string]interface{})
	require.True(t, ok, "Content should have request block")

	// Verify HTTP method
	method, ok := request["method"].(string)
	require.True(t, ok, "Request should have method field")
	assert.Equal(t, "POST", method, "HTTP method should be POST")

	// Verify request body
	body, ok := request["body"].(string)
	require.True(t, ok, "Request should have body field")
	assert.Equal(t, `{"text":""}`, body, "Request body should be empty text JSON")

	// Verify headers
	headers, ok := request["headers"].(map[string]interface{})
	require.True(t, ok, "Request should have headers")
	contentType, ok := headers["Content-Type"].(string)
	require.True(t, ok, "Headers should have Content-Type")
	assert.Equal(t, "application/json", contentType, "Content-Type should be application/json")

	// Verify URL template
	urlTemplate, ok := request["url"].(string)
	require.True(t, ok, "Request should have url field")
	assert.Equal(t, "{{ TOKEN }}", urlTemplate, "URL should use {{ TOKEN }} template")

	// Verify response matchers
	responseMatchers, ok := request["response_matcher"].([]interface{})
	require.True(t, ok, "Request should have response_matcher array")
	require.Len(t, responseMatchers, 2, "Should have 2 response matchers")

	// Verify StatusMatch matcher
	statusMatcher, ok := responseMatchers[0].(map[string]interface{})
	require.True(t, ok, "First matcher should be a map")
	statusType, ok := statusMatcher["type"].(string)
	require.True(t, ok, "Matcher should have type")
	assert.Equal(t, "StatusMatch", statusType, "First matcher should be StatusMatch")

	statusCodes, ok := statusMatcher["status"].([]interface{})
	require.True(t, ok, "StatusMatch should have status array")
	require.Len(t, statusCodes, 1, "Should have 1 status code")
	assert.Equal(t, 400, statusCodes[0], "Status code should be 400")

	// Verify WordMatch matcher
	wordMatcher, ok := responseMatchers[1].(map[string]interface{})
	require.True(t, ok, "Second matcher should be a map")
	wordType, ok := wordMatcher["type"].(string)
	require.True(t, ok, "Matcher should have type")
	assert.Equal(t, "WordMatch", wordType, "Second matcher should be WordMatch")

	words, ok := wordMatcher["words"].([]interface{})
	require.True(t, ok, "WordMatch should have words array")
	require.Len(t, words, 1, "Should have 1 word")
	assert.Equal(t, "Text is required", words[0], "Word should be 'Text is required'")

	reportResponse, ok := wordMatcher["report_response"].(bool)
	require.True(t, ok, "WordMatch should have report_response")
	assert.True(t, reportResponse, "report_response should be true")
}

// TestKingfisherMicrosoftTeamsWebhook_ValidationBlock verifies validation YAML structure
func TestKingfisherMicrosoftTeamsWebhook_ValidationBlock(t *testing.T) {
	// Load the microsoftteamswebhook.yml file
	data, err := builtinRulesFS.ReadFile("rules/microsoftteamswebhook.yml")
	require.NoError(t, err, "Failed to read microsoftteamswebhook.yml")

	// Parse the raw YAML to access validation structure
	var yamlFile map[string]interface{}
	err = yaml.Unmarshal(data, &yamlFile)
	require.NoError(t, err, "Failed to parse microsoftteamswebhook.yml")

	rules, ok := yamlFile["rules"].([]interface{})
	require.True(t, ok, "YAML should have 'rules' array")
	require.NotEmpty(t, rules, "Rules array should not be empty")

	// Get the first rule (kingfisher.microsoftteamswebhook.1)
	rule, ok := rules[0].(map[string]interface{})
	require.True(t, ok, "Rule should be a map")

	// Verify validation block exists and has same structure as np.msteams.1
	validation, ok := rule["validation"].(map[string]interface{})
	require.True(t, ok, "Rule should have validation block")

	validationType, ok := validation["type"].(string)
	require.True(t, ok, "Validation should have type field")
	assert.Equal(t, "Http", validationType, "Validation type should be Http")

	content, ok := validation["content"].(map[string]interface{})
	require.True(t, ok, "Validation should have content block")

	request, ok := content["request"].(map[string]interface{})
	require.True(t, ok, "Content should have request block")

	method, ok := request["method"].(string)
	require.True(t, ok, "Request should have method field")
	assert.Equal(t, "POST", method, "HTTP method should be POST")

	body, ok := request["body"].(string)
	require.True(t, ok, "Request should have body field")
	assert.Equal(t, `{"text":""}`, body, "Request body should match expected format")
}
