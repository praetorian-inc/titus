#!/usr/bin/env bash
# Assigns every rule in all_rules.csv to a batch.
# Emits per-batch JSON files and a summary.

set -euo pipefail

RESEARCH_DIR="$(cd "$(dirname "$0")" && pwd)"
ALL_RULES="/tmp/all_rules.csv"

# Service → batch ID mapping. One entry per service prefix we've seen.
# Services NOT listed here go to B19 (long-tail SaaS) as a catchall.
declare -A MAP

# B01 Cloud infrastructure
for s in aws azure azurestorage azureopenai azuresearch azuresearchquery azuredevops azure-notification-hub gcp gcs s3 appsync arn alibabacloud alibaba; do MAP[$s]=B01; done

# B02 Private keys, crypto, password hashes
for s in pem privkey age pwhash krb5 wireguard coinbase 1password; do MAP[$s]=B02; done

# B03 Payments & financial
for s in stripe paypal square razorpay plaid paystack gocardless duffel easypost gumroad finicity shippo lob bitly; do MAP[$s]=B03; done

# B04 Source control
for s in github gitlab bitbucket atlassian gitter gitalk; do MAP[$s]=B04; done

# B05 CI/CD & build artifacts
for s in jenkins circleci travisci buildkite coveralls codecov codeclimate codacy drone dockerhub docker npm pypi rubygems cratesio nuget artifactory packagecloud clojars mergify coderabbit sonarqube sonarcloud teamcity appcenter gradle scalingo stackhawk snyk sauce browserstack cypress pulumi infracost; do MAP[$s]=B05; done

# B06 Communication / chat / collab
for s in slack mattermost discord msteams microsoftteamswebhook telegram line sendbird messagebird linear notion lark monday asana jira calendly; do MAP[$s]=B06; done

# B07 AI/ML services tier A
for s in openai anthropic cohere mistral huggingface perplexity groq together stabilityai ollama openrouter replicate cerebras ai21studio baseten deepseek zhipu fireworks friendli xai runway vastai; do MAP[$s]=B07; done

# B08 AI/ML services tier B (utilities, tooling)
for s in cursor clarifai assemblyai deepgram elevenlabs jina langchain voyageai tavily exa klingai wandb retellai scraperapi pdflayer imagekit; do MAP[$s]=B08; done

# B09 Email/messaging/marketing
for s in sendgrid mailgun mailchimp mailjet postmark sendinblue resend twilio mandrill klaviyo iterable customerio pendo delighted beamer eventbrite intercom helpscout zendesk freshdesk pagerduty opsgenie statuspage; do MAP[$s]=B09; done

# B10 Observability / metrics / APM
for s in newrelic datadog sentry honeycomb grafana dtrack amplitude posthog segment wakatime dynatrace; do MAP[$s]=B10; done

# B11 Databases & caching
for s in postgres mysql mongodb clickhouse supabase planetscale databricks jdbc odbc rabbitmq; do MAP[$s]=B11; done

# B12 Feature flags / ops / secrets mgmt
for s in launchdarkly optimizely harness doppler hashicorp kubernetes vmware definednetworking authress auth0 okta cloudflare jumpcloud intra42; do MAP[$s]=B12; done

# B13 E-commerce / CRM
for s in shopify salesforce hubspot zoho zohocrm zuplo typeform jotform; do MAP[$s]=B13; done

# B14 Maps / geo / IP / weather
for s in mapbox hereapi openweather maxmind ipstack ngrok tailscale shodan; do MAP[$s]=B14; done

# B15 Social media
for s in linkedin twitter facebook instagram youtube twitch reddit pinterest nasa nytimes guardian foursquare deviantart flickr yelp datagov; do MAP[$s]=B15; done

# B16 IoT / embedded / hardware
for s in particleio blynk thingsboard truenas riot adafruit aiven adobe; do MAP[$s]=B16; done

# B17 Storage / sync / files
for s in dropbox fileio; do MAP[$s]=B17; done

# B18 Identity / auth / API management (residuals after B12)
for s in apollo postman apify clay diffbot ionic fastly frame frameio figma airtable krb5; do MAP[$s]=B18; done

# B20 Generic patterns & primitives
for s in generic credentials http netrc curl jwt uri filezilla phpmailer psexec reactapp; do MAP[$s]=B20; done

# Generate per-batch rule JSON
mkdir -p "$RESEARCH_DIR/batches"
declare -A COUNTS
unbatched=""
while IFS=, read -r rule_id rule_name yaml_file; do
    [ "$rule_id" = "rule_id" ] && continue # skip header
    service="${rule_id#np.}"
    service="${service#kingfisher.}"
    service="${service%%.*}"

    batch="${MAP[$service]:-B19}" # default to B19 long-tail
    COUNTS[$batch]=$((${COUNTS[$batch]:-0} + 1))

    # Append JSON line to batch's input file (will be rewrapped to array below)
    echo "{\"id\":\"$rule_id\",\"name\":$(printf '%s' "$rule_name" | jq -Rs .),\"yaml_file\":\"$yaml_file\"}" >> "$RESEARCH_DIR/batches/${batch}.jsonl"
    if [ "$batch" = "B19" ] && [ -z "${MAP[$service]:-}" ]; then
        unbatched="$unbatched$service "
    fi
done < "$ALL_RULES"

# Wrap each .jsonl into a proper .json array
for f in "$RESEARCH_DIR/batches/"*.jsonl; do
    [ -e "$f" ] || continue
    batch=$(basename "$f" .jsonl)
    jq -s '.' "$f" > "$RESEARCH_DIR/batches/${batch}.json"
    rm -f "$f"
done

echo "Batch summary:"
for batch in B01 B02 B03 B04 B05 B06 B07 B08 B09 B10 B11 B12 B13 B14 B15 B16 B17 B18 B19 B20; do
    echo "  $batch: ${COUNTS[$batch]:-0} rules"
done
echo ""
echo "Unbatched services landed in B19:"
echo "$unbatched" | tr ' ' '\n' | sort -u | grep -v '^$' | tr '\n' ' '
echo ""
