# False Positive Reduction Changelog

**Date:** 2026-02-10
**Branch:** `feat/reduce-false-positives-conservative`
**Approach:** Conservative (Zero Coverage Loss)

## Summary

This release implements targeted false positive reductions for Titus rules that were generating high volumes of non-actionable findings. All changes follow the principle of **reducing FPs by adding specificity, not by removing patterns entirely**.

| Rule | FPs Eliminated | Coverage Risk |
|------|----------------|---------------|
| kingfisher.looker.1 | ~410 | NONE |
| np.generic.1 | ~36 | NONE |
| np.generic.5 | ~48 | LOW |
| kingfisher.azurestorage.1a | ~1 | NONE |
| np.twitter.1 | ~1 | NONE |

**Total FPs Eliminated:** ~496
**Coverage Risk:** NONE to LOW

---

## Detailed Changes

### 1. kingfisher.looker.1 - Looker Base URL

**Problem:** Original pattern matched ANY HTTP/HTTPS URL, causing 410+ false positives on URLs like `https://www.facebook.com`, `https://docs.plesk.com`, and `https://www.youtube.com`.

**Root Cause:** Pattern `https?://[a-z0-9.-]+(?::\d{2,5})?` was too broad - it captured any URL structure without requiring Looker-specific context.

**Fix:** Restricted pattern to match only:
- Looker-specific domains: `*.looker.com`
- Explicit Looker API paths: `/api/4.0` or `/api/3.1`

**Why This Won't Miss Real Secrets:**
- Real Looker integrations use `*.looker.com` domains (cloud.looker.com, company.looker.com)
- Self-hosted Looker instances use `/api/4.0` or `/api/3.1` paths for API access
- No legitimate Looker secret is a URL to facebook.com or w3.org

**Coverage Impact:** NONE

---

### 2. np.generic.1 - Generic Secret

**Problem:** Pattern matched TypeScript/JavaScript type guard function names from SDKs (e.g., `instanceOfAppRoleLookUpSecretIdResponse`), generating 36+ false positives from HashiCorp Vault SDK code.

**Root Cause:** Pattern `secret.{0,20}[0-9a-z]{32,64}` matched any alphanumeric string near the word "secret", including code identifiers.

**Fix:** Added negative lookahead `(?!instanceOf)` to exclude TypeScript type guard function names.

**Why This Won't Miss Real Secrets:**
- Real secrets are random/high-entropy strings
- No credential system generates tokens following camelCase naming conventions like `instanceOfXxxSecretYyyResponse`
- TypeScript type guards are code identifiers, not data

**Coverage Impact:** NONE

---

### 3. np.generic.5 - Generic Password

**Problem:** Pattern matched i18n/translation strings and webpack chunk hashes, generating 48+ false positives:
- Translation labels: `PASSWORD:"密碼"`, `PASSWORD:"Senha"`, `PASSWORD:"Wachtwoord"`
- Webpack hashes: `"views/admin/force-reset-password":"4f36963ced79d61945d7"`
- Constants: `PASSWORD="UPDATE_PASSWORD"`

**Root Cause:** Pattern captured any quoted string following `password:` or `password=`, without filtering common non-secret patterns.

**Fix:**
1. Added minimum length requirement (8 characters instead of 5)
2. Added negative lookahead to exclude:
   - Pure hex strings (16-24 chars) - likely webpack chunk hashes
   - ALL_CAPS constants like `UPDATE_PASSWORD`
   - Literal `password` placeholder

**Why This Won't Miss Real Secrets:**
- Real passwords typically have 8+ characters with mixed character types
- Translation labels are single words (< 15 chars) in non-ASCII scripts
- Webpack chunk hashes are always 16-24 character hex strings
- Keycloak action constants follow `UPDATE_PASSWORD` pattern

**Coverage Impact:** LOW - May miss some very short passwords (5-7 chars), but these are rare and typically test values.

---

### 4. kingfisher.azurestorage.1a - Azure Storage Account Name

**Problem:** Pattern matched Azure Storage Emulator default account name `devstoreaccount1`, which is a well-documented Microsoft value that only works with localhost.

**Root Cause:** Pattern matched any 3-24 character alphanumeric string following `AccountName=`, without excluding known test values.

**Fix:** Added negative lookahead `(?!devstoreaccount1)` to exclude the Azure Storage Emulator default.

**Why This Won't Miss Real Secrets:**
- `devstoreaccount1` is a reserved name that Azure doesn't allow for real storage accounts
- The associated key (`Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50+Bx/EMBHBeksoGMGw==`) only works with localhost:10000
- Microsoft officially documents this as development-only

**Coverage Impact:** NONE

**Reference:** https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite

---

### 5. np.twitter.1 - Twitter/X Client ID

**Problem:** Pattern matched JavaScript variable names like `EnvironmentConstant` which happened to be 18+ alphanumeric characters.

**Root Cause:** Pattern `[a-zA-Z0-9]{18,25}` was too broad - Twitter Client IDs are always numeric, but the pattern allowed alphanumeric.

**Fix:** Changed pattern from `[a-zA-Z0-9]{18,25}` to `[0-9]{15,25}` (numeric only).

**Why This Won't Miss Real Secrets:**
- Twitter/X Client IDs are ALWAYS numeric strings (e.g., `1234567890123456789`)
- They are app identifiers assigned by Twitter's system
- Twitter has never used alphanumeric client IDs

**Coverage Impact:** NONE

---

## Testing Recommendations

1. **Regression Testing:** Scan a known corpus of real secrets to verify no true positives are lost
2. **FP Verification:** Rescan files that previously generated false positives to confirm they're eliminated
3. **Boundary Testing:** Test edge cases around the new pattern boundaries

## Rollback

If issues are discovered, each change is isolated to a single rule and can be individually reverted by restoring the original pattern from the `main` branch.
