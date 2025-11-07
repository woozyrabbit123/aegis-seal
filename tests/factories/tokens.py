"""Runtime token generators for testing secret detection.

These functions generate fake tokens that match detection patterns but are
NOT real secrets. Generated at test runtime to avoid GitHub push protection.
"""

import secrets
import string


def _rand(alphabet: str, length: int) -> str:
    """Generate random string from alphabet."""
    return ''.join(secrets.choice(alphabet) for _ in range(length))


# Character sets
HEX = "0123456789abcdef"
HEX_UPPER = "0123456789ABCDEF"
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
BASE62 = string.ascii_letters + DIGITS
BASE64_CHARS = BASE62 + "+/="


# Cloud Providers
def gcp_service_account() -> str:
    """Generate GCP service account JSON structure."""
    return '''{
  "type": "service_account",
  "project_id": "test-project-fake",
  "private_key_id": "fake123abc456"
}'''


def gcp_api_key() -> str:
    """Generate fake GCP API key."""
    return "AIzaSy" + _rand(BASE62, 33)


def azure_storage_connection_string() -> str:
    """Generate fake Azure storage connection string."""
    return f"DefaultEndpointsProtocol=https;AccountName=fakeaccount;AccountKey={_rand(BASE64_CHARS, 88)}"


def k8s_token() -> str:
    """Generate fake Kubernetes token (JWT format)."""
    header = _rand(BASE62, 20)
    payload = _rand(BASE62, 30)
    signature = _rand(BASE62, 25)
    return f"eyJ{header}.eyJ{payload}.{signature}"


# Development Platforms
def gitlab_pat() -> str:
    """Generate fake GitLab PAT."""
    return "glpat-" + _rand(BASE62, 20)


def gitlab_runner_token() -> str:
    """Generate fake GitLab runner token."""
    return "GR1348941" + _rand(BASE62, 20)


def bitbucket_client_secret() -> str:
    """Generate fake Bitbucket client secret."""
    return _rand(BASE62, 32)


def npm_token() -> str:
    """Generate fake NPM token."""
    return "npm_" + _rand(BASE62, 36)


def pypi_token() -> str:
    """Generate fake PyPI token."""
    return "pypi-AgEIcHlwaS5vcmc" + _rand(BASE62 + "_-", 70)


def docker_pat() -> str:
    """Generate fake Docker PAT."""
    return "dckr_pat_" + _rand(BASE62 + "_-", 32)


def dsa_private_key_header() -> str:
    """Generate DSA private key header."""
    return "-----BEGIN DSA PRIVATE KEY-----"


def ec_private_key_header() -> str:
    """Generate EC private key header."""
    return "-----BEGIN EC PRIVATE KEY-----"


# SaaS Providers
def twilio_api_key() -> str:
    """Generate fake Twilio API key."""
    return "SK" + _rand(LOWERCASE + DIGITS, 32)


def twilio_account_sid() -> str:
    """Generate fake Twilio Account SID."""
    return "AC" + _rand(LOWERCASE + DIGITS, 32)


def discord_webhook() -> str:
    """Generate fake Discord webhook URL."""
    webhook_id = _rand(DIGITS, 18)
    webhook_token = _rand(BASE62 + "_-", 68)
    return f"https://discord.com/api/webhooks/{webhook_id}/{webhook_token}"


def discord_bot_token() -> str:
    """Generate fake Discord bot token."""
    part1 = "M" + _rand(BASE62 + "_-", 23)
    part2 = _rand(BASE62 + "_-", 6)
    part3 = _rand(BASE62 + "_-", 27)
    return f"{part1}.{part2}.{part3}"


def auth0_client_secret() -> str:
    """Generate fake Auth0 client secret."""
    return _rand(BASE62 + "_-", 64)


def openai_api_key() -> str:
    """Generate fake OpenAI API key."""
    return "sk-" + _rand(BASE62, 48)


def heroku_api_key() -> str:
    """Generate fake Heroku API key (UUID format)."""
    return f"{_rand(HEX, 8)}-{_rand(HEX, 4)}-{_rand(HEX, 4)}-{_rand(HEX, 4)}-{_rand(HEX, 12)}"


def shopify_access_token() -> str:
    """Generate fake Shopify access token."""
    return "shpat_" + _rand(HEX, 32)


def shopify_shared_secret() -> str:
    """Generate fake Shopify shared secret."""
    return "shpss_" + _rand(HEX, 32)


def sendgrid_api_key() -> str:
    """Generate fake SendGrid API key."""
    part1 = _rand(BASE62 + "_-", 22)
    part2 = _rand(BASE62 + "_-", 43)
    return f"SG.{part1}.{part2}"


def mailgun_api_key() -> str:
    """Generate fake Mailgun API key."""
    return "key-" + _rand(LOWERCASE + DIGITS, 32)


def square_access_token() -> str:
    """Generate fake Square access token."""
    return "sq0atp-" + _rand(BASE62 + "_-", 22)


def square_oauth_secret() -> str:
    """Generate fake Square OAuth secret."""
    return "sq0csp-" + _rand(BASE62 + "_-", 43)


# GitHub (for reference tests)
def github_pat() -> str:
    """Generate fake GitHub PAT."""
    return "ghp_" + _rand(BASE62, 36)


def github_oauth() -> str:
    """Generate fake GitHub OAuth token."""
    return "gho_" + _rand(BASE62, 36)
