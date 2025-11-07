"""Sample application with hardcoded secrets (for testing)."""

import requests


class Config:
    """Application configuration."""

    # GitHub token (will be detected - FAKE EXAMPLE)
    GITHUB_TOKEN = "ghp_EXAMPLE_FAKE_TOKEN_FOR_TESTING_ONLY"

    # AWS credentials (will be detected - FAKE EXAMPLE)
    AWS_ACCESS_KEY_ID = "AKIA_EXAMPLE_NOT_REAL_KEY"
    AWS_SECRET_ACCESS_KEY = "example/secret/key/not/real/value"

    # API key (will be detected - FAKE EXAMPLE)
    API_KEY = "sk_test_FAKE_EXAMPLE_KEY_NOT_REAL"


def fetch_data():
    """Fetch data from API."""
    headers = {
        "Authorization": f"Bearer {Config.GITHUB_TOKEN}",
        "X-API-Key": Config.API_KEY,
    }

    response = requests.get("https://api.example.com/data", headers=headers)
    return response.json()


def main():
    """Main function."""
    data = fetch_data()
    print(data)


if __name__ == "__main__":
    main()
