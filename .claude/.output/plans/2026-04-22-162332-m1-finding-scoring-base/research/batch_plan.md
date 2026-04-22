# Research Batch Plan

**Total to score:** 491 rules across 297 distinct services.

## Batching principle

Group by **research domain** (payments, cloud, observability, etc.) rather than
arbitrary size. A single research subagent handles one coherent domain so it
can apply consistent scoring logic within the domain. Most services have 1
rule and share a single base score; a few services (AWS, GCP, GitHub) have
multiple rules requiring per-rule differentiation (e.g., AWS account ID vs.
secret access key).

Each batch targets roughly 20-30 rules so a single research agent's output
stays reviewable. Smaller, coherent batches beat larger heterogeneous ones.

## Batches

| # | Batch | Services | Rule count | Per-rule differentiation needed? |
|---|-------|----------|------------|----------------------------------|
| B01 | **Cloud infrastructure (AWS/GCP/Azure)** | aws, azure, azurestorage, azureopenai, azuresearch, gcp, gcs, s3, appsync, arn, azure-notification-hub | ~32 | YES (aws.1=id, aws.2=secret, etc.) |
| B02 | **Private keys, crypto, password hashes** | pem, privkey, age, pwhash, krb5, wireguard, coinbase, 1password | ~20 | Per-rule (pem vs pwhash differ) |
| B03 | **Payments & financial** | stripe, paypal, square, razorpay, plaid, paystack, gocardless, duffel, easypost, gumroad, finicity, shippo, lob, bitly | ~20 | Mostly service-level |
| B04 | **Source control (GitHub/GitLab/Bitbucket)** | github, gitlab, bitbucket, atlassian, gitter, gitalk | ~15 | YES (github.3 ghs_ vs github.1 ghp_ differ in scope) |
| B05 | **CI/CD & build artifacts** | jenkins, circleci, travisci, buildkite, coveralls, codecov, codeclimate, codacy, drone, gradle, docker, dockerhub, npm, pypi, rubygems, cratesio, nuget, artifactory, packagecloud, clojars, mergify, coderabbit, sonarqube, sonarcloud, teamcity, appcenter | ~30 | Mostly service-level |
| B06 | **Communication/chat** | slack, mattermost, discord, msteams, microsoftteamswebhook, telegram, line, sendbird, messagebird, linear, notion, lark, monday, clickup, asana, jira, calendly, confluence | ~30 | YES (slack bot/user tokens differ) |
| B07 | **AI/ML services tier A (major)** | openai, anthropic, google-palm, cohere, mistral, huggingface, perplexity, groq, together, stabilityai, ollama, openrouter, replicate, cerebras, ai21studio, baseten, deepseek, zhipu, fireworks, friendli, xai, runway, vastai | ~24 | Service-level (all similar: LLM API keys) |
| B08 | **AI/ML services tier B (utilities)** | cursor, clarifai, assemblyai, deepgram, elevenlabs, jina, langchain, voyageai, tavily, exa, klingai, wandb, deepgram, retellai, scraperapi, pdflayer, imagekit | ~18 | Service-level |
| B09 | **Email / messaging / marketing** | sendgrid, mailgun, mailchimp, mailjet, postmark, sendinblue, resend, twilio, mandrill, klaviyo, iterable, customerio, pendo, delighted, beamer, eventbrite, intercom, helpscout, zendesk, freshdesk, pagerduty, opsgenie, statuspage, frontapp, gocardless | ~28 | Service-level |
| B10 | **Observability, metrics, APM** | newrelic, datadog, sentry, honeycomb, grafana, dtrack, amplitude, posthog, segment, wakatime, dynatrace, infracost | ~30 | Service-level (mostly single tier) |
| B11 | **Databases & caching & streaming** | postgres, mysql, mongodb, clickhouse, supabase, planetscale, databricks, jdbc, odbc, rabbitmq, redis, elasticsearch, snowflake | ~18 | Service-level |
| B12 | **Feature flags & ops tools** | launchdarkly, optimizely, harness, figma, airtable, typeform, pulumi, scalingo, pypi, stackhawk, shodan, bitbucket, doppler, hashicorp, vault, kubernetes, nomad, consul, vmware | ~30 | YES (hashicorp has 7 rules with different token types, doppler 6) |
| B13 | **E-commerce / retail / CRM** | shopify, salesforce, hubspot, zoho, zohocrm, zuplo, pipedrive, marketo, jotform, gitHub Marketplace | ~12 | YES (shopify has 5 rules - access token types differ) |
| B14 | **Maps / geo / IP / weather** | mapbox, hereapi, openweather, maxmind, ipstack, ngrok, tailscale, shippo, geocoding services | ~15 | Service-level |
| B15 | **Social media** | linkedin, twitter, facebook, instagram, youtube, twitch, reddit, pinterest, nasa, nytimes, guardian, foursquare, deviantart, flickr, yelp | ~25 | Service-level |
| B16 | **IoT / embedded / hardware** | particle.io, blynk, thingsboard, truenas, riot, adafruit, aiven, riotgames, flyio | ~20 | Service-level (blynk has 5 rules, thingsboard 3) |
| B17 | **Storage / sync / files** | dropbox, box, imagekit, gcs, s3 (if not in B01), cloudinary, transloadit, fileio, easypost | ~8 | Service-level |
| B18 | **Security tooling & API mgmt** | authress, auth0, okta, cloudflare, 1password, apollo, postman, apify, perplexity, clay, diffbot, ionic, stackhawk, definednetworking | ~15 | Per-rule for auth0, okta |
| B19 | **Long-tail SaaS (1-rule each, misc)** | calendly, typeform, calendly, eventbrite, statuspage, pagerduty, linear, gitter, monday, intra42, scale, loom, screencastify, zuplo, coze, fleetbase, hubspot, wpengine, sauce, browserstack, cypress, vercel, heroku, linode, digitalocean, scale, owlbot, etc. | ~50 | Service-level |
| B20 | **Generic patterns & rule primitives** | generic (16 rules — credential patterns without specific vendor), credentials, http, netrc, curl, jwt, uri, filezilla, phpmailer, psexec, s3 (if not B01), frontend-reactapp, kubernetes (if not B12) | ~35 | Per-rule (jwt.1 vs jwt.2 etc.) |

## Totals (approximate; actual numbers resolved at dispatch time)

- ~491 rules across 20 batches
- Avg: ~25 rules/batch
- Max: ~50 rules (long-tail SaaS in B19, expected to be fast since most are clear "tier 2 SaaS" scoring)
- Parallelism: 20 subagents; expected wall-clock 15-30 min

## Research method per subagent

Each subagent uses `core:research` skill to investigate the real-world capabilities
of each secret class. The research agent will:

1. Read the rule YAML for description + references
2. Consult vendor documentation (the references field typically links there)
3. Assess blast radius, financial impact, authorization scope
4. Assign a tier (info/low/medium/high/critical) + integer score per rule

The standardized prompt template (see `subagent_prompt_template.md`) emphasizes:
- Use of the 5-tier system
- Differentiation (subagent must vary scores within batch)
- LOW CONFIDENCE marking for uncertain rules
- Output format: CSV with `rule_id,base_score,tier,reasoning`

## Known differentiation hotspots

These services have multiple rules where scores should differ:

| Service | Rules | Expected score pattern |
|---|---|---|
| AWS | 6 rules | Account ID (info ~10), API Key ID (medium ~50), Secret Access Key (critical ~90), Session Token (high ~75), AppSync (high ~70) |
| GitHub | 7 rules | PAT classic (high ~70), OAuth (high ~70), App server-to-server ghs_ (critical ~85), App user-to-server ghu_ (high ~70), Refresh token (medium ~50), Client ID (info ~15), Secret key (critical ~85) |
| Slack | 7 rules | Bot token (high ~70), User token (high ~70), Webhook (medium ~50), etc. |
| HashiCorp Vault | 7 rules | Service token (critical ~90), Batch token (high ~70), Unseal key (critical ~95), etc. |
| Doppler | 6 rules | Personal, Service, CLI, SCIM, Audit tokens — varying admin scope |
| Shopify | 5 rules | Access tokens, App secrets, varies by scope |
| Blynk | 5 rules | Device vs Organization tokens |
| Plaid | 5 rules | Production secret > Sandbox > Client ID |
| MongoDB | 5 rules | Connection strings vs API tokens |
| Generic | 16 rules | Each is a different pattern class (password, API key, secret) — medium default |
| JWT | 3 rules | Token vs secret differ |
| PEM | 2 rules | Private key = critical; base64-encoded = critical |
| AGE | 2 rules | Identity key vs public |
| 1Password | 2 rules | Service account vs secret key |

## Approval checkpoint

This plan is presented for **human review before dispatching subagents**.
Once approved, the orchestrator:
1. Extracts per-batch rule lists into JSON
2. Dispatches 20 `core:research` subagents in parallel using the standard prompt
3. Waits for all to complete
4. Validates + merges into master `scores.csv`
