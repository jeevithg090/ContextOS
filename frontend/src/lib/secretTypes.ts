/**
 * Display labels for the secret types the redaction engine emits — the `<type>` in
 * "[REDACTED:<type>:<fp8>]" markers and in `secret_types` summaries. Sources:
 * backend/app/engines/redaction/patterns.py (provider tokens and structured credentials),
 * contextual.py (assignments such as `password = ...`) and engine.py (`sensitive_field`, a value
 * stored under a credential-named key). `src/lib/__tests__/domainSync.test.ts` fails when the engine
 * gains a type that has no label here.
 */
export const SECRET_TYPE_LABELS: Record<string, string> = {
  // Provider-prefixed tokens
  anthropic_api_key: "Anthropic API key",
  aws_access_key: "AWS access key ID",
  contextos_api_key: "ContextOS API key",
  contextos_session_token: "ContextOS session token",
  databricks_token: "Databricks token",
  digitalocean_token: "DigitalOcean token",
  discord_webhook: "Discord webhook URL",
  docker_hub_token: "Docker Hub token",
  github_token: "GitHub token",
  gitlab_token: "GitLab token",
  google_api_key: "Google API key",
  google_oauth_client_secret: "Google OAuth client secret",
  google_oauth_token: "Google OAuth access token",
  groq_api_key: "Groq API key",
  huggingface_token: "Hugging Face token",
  linear_api_key: "Linear API key",
  npm_token: "npm token",
  openai_api_key: "OpenAI API key",
  pypi_token: "PyPI token",
  sendgrid_api_key: "SendGrid API key",
  shopify_token: "Shopify token",
  slack_token: "Slack token",
  slack_webhook: "Slack webhook URL",
  stripe_live_key: "Stripe live key",
  stripe_test_key: "Stripe test key",
  stripe_webhook_secret: "Stripe webhook secret",
  supabase_token: "Supabase token",
  telegram_bot_token: "Telegram bot token",
  twilio_api_key: "Twilio API key",
  vault_token: "HashiCorp Vault token",
  xai_api_key: "xAI API key",
  // Structured credentials
  private_key: "Private key",
  jwt: "JSON Web Token",
  database_credentials: "Database credentials",
  url_credentials: "Credentials in a URL",
  azure_storage_key: "Azure storage account key",
  azure_shared_access_key: "Azure shared access key",
  azure_sas_token: "Azure SAS token",
  basic_auth: "HTTP Basic credentials",
  bearer_token: "Bearer token",
  session_cookie: "Session cookie",
  password_hash: "Password hash",
  // Context-based (assignments, provider-specific variable names)
  aws_secret_key: "AWS secret access key",
  twilio_auth_token: "Twilio auth token",
  generic_password: "Password",
  generic_api_key: "API key",
  generic_token: "Access token",
  generic_secret: "Secret",
  // Structured payloads: the value of a credential-named field (password, token, api_key, ...)
  sensitive_field: "Sensitive field value",
};

/** Human label for a secret type; unknown types are shown readably rather than hidden. */
export function secretTypeLabel(type?: string | null): string {
  if (!type) return "Secret";
  const known = SECRET_TYPE_LABELS[type];
  if (known) return known;
  const spaced = type.replace(/_/g, " ").trim();
  return spaced ? spaced.charAt(0).toUpperCase() + spaced.slice(1) : "Secret";
}
