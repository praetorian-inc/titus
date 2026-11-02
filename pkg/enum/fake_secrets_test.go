package enum

import "strings"

// The fixtures below are fake credentials that the scanner under test must
// find. They are assembled at run time so this repository's source holds no
// literal that its own secret scan reports; the bytes written to fixture
// files and fed to the scanner are unchanged.

// fakeGitHubToken returns a classic GitHub personal access token made of 36
// copies of c.
func fakeGitHubToken(c byte) string {
	return "ghp_" + strings.Repeat(string(c), 36)
}

// fakeTokenLine returns a "TOKEN=<token>\n" line holding fakeGitHubToken(c).
func fakeTokenLine(c byte) string {
	return "TOKEN=" + fakeGitHubToken(c) + "\n"
}

// fakeUserinfo is the user:password part of the credential-bearing clone
// URLs in these tests. Joining it to a scheme and host with "@" yields the
// same URL bytes as writing that URL as one literal.
const fakeUserinfo = "u" + ":" + "secret"

// fakeCredURL returns scheme://fakeUserinfo@rest, e.g. fakeCredURL("https",
// "github.com/acme/api.git").
func fakeCredURL(scheme, rest string) string {
	return scheme + "://" + fakeUserinfo + "@" + rest
}
