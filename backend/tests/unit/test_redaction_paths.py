"""is_sensitive_path matrix and classify_sensitivity (SECRET / CONFIDENTIAL / INTERNAL / PUBLIC)."""

from __future__ import annotations

import random
import string

import pytest

from app.domain.enums import Sensitivity
from app.engines.redaction import SecretMatch, classify_sensitivity, detect_secrets, is_sensitive_path

SENSITIVE = [
    ".env", "./.env", "/srv/app/.env.local", ".env.production", "config/prod.env", ".envrc",
    "~/.ssh/id_rsa", "/home/dev/.ssh/id_ed25519", "C:\\Users\\bob\\.ssh\\config", "/root/.ssh/authorized_keys",
    "id_rsa", "deploy/id_ecdsa", "~/.aws/credentials", "$HOME/.aws/config", "%USERPROFILE%\\.aws\\credentials",
    "certs/server.pem", "tls/private.key", "keystore.p12", "client.pfx", "vault.kdbx", "~/.npmrc", ".pypirc",
    "~/.netrc", "~/.git-credentials", "~/.docker/config.json", "kubeconfig", "~/.kube/config",
    "~/.config/gcloud/application_default_credentials.json", "infra/terraform.tfstate",
    "infra/terraform.tfstate.backup", "config/secrets.yml", "k8s/db-secrets.yaml", "credentials.json",
    "service-account-prod.json", "/etc/shadow", "/etc/passwd", "../../../../etc/passwd", "wallet.dat",
    "~/Library/Application Support/Google/Chrome/Default/Login Data",
    "~/Library/Application Support/Google/Chrome/Default/Cookies", "profile/cookies.sqlite", "~/.zsh_history",
    "/proc/self/environ", "file:///home/u/.env", "~/.ssh/*", "C:/Windows/System32/config/SAM",
    "~/.ssh/known_hosts", "~/.ssh/*.pub", "~/.ssh/.pub", "~/.ssh/deploy_key",
]
NOT_SENSITIVE = [
    ".env.example", ".env.sample", ".env.template", "example.env", "README.md", "src/app/main.py",
    "id_rsa.pub", "docs/environment.md", "package.json", "config/settings.yaml", "~/.bashrc",
    "public/cookies-policy.html", "src/keys.py", "tokenizer.json", "", "/etc/hosts",
    "~/.ssh/id_ed25519.pub", "/home/dev/.ssh/id_rsa.pub", "C:\\Users\\bob\\.ssh\\deploy_key.PUB",
]


@pytest.mark.parametrize("path", SENSITIVE)
def test_sensitive_paths_are_recognised_with_a_reason(path):
    sensitive, reason = is_sensitive_path(path)
    assert sensitive is True, path
    assert reason and len(reason) > 8


@pytest.mark.parametrize("path", NOT_SENSITIVE)
def test_ordinary_paths_are_not_flagged(path):
    assert is_sensitive_path(path) == (False, None)


def test_ssh_files_explain_why_they_matter_and_public_keys_are_not_secrets():
    assert "known_hosts" in is_sensitive_path("~/.ssh/known_hosts")[1]
    assert "grants access" in is_sensitive_path("/root/.ssh/authorized_keys")[1]
    assert "private key" in is_sensitive_path("~/.ssh/config")[1]
    assert is_sensitive_path("~/.ssh/id_rsa")[1] == "SSH directory — private keys and client configuration"
    assert is_sensitive_path("~/.ssh/id_rsa.pub") == (False, None)
    assert is_sensitive_path("keys/id_rsa.pub.pem")[0]  # the .pem rule still applies outside ~/.ssh


def test_path_matching_is_case_and_separator_insensitive():
    assert is_sensitive_path("C:\\USERS\\Bob\\.SSH\\ID_RSA")[0]
    assert is_sensitive_path('"~/.aws/credentials"')[1] == is_sensitive_path("/Users/alice/.aws/credentials")[1]


# --- classification ---------------------------------------------------------------------------

_RNG = random.Random(99)


def _gh() -> str:
    return "ghp_" + "".join(_RNG.choice(string.ascii_letters + string.digits) for _ in range(36))


def _match(confidence: float) -> SecretMatch:
    return SecretMatch("generic_token", 0, 4, "0" * 16, confidence)


def test_high_confidence_secret_is_secret():
    text = f"deploy with {_gh()}"
    assert classify_sensitivity(text, detect_secrets(text)) == Sensitivity.SECRET


def test_low_confidence_match_is_confidential():
    assert classify_sensitivity("x", [_match(0.5)]) == Sensitivity.CONFIDENTIAL


def test_sensitive_identifier_without_secrets_is_confidential():
    assert classify_sensitivity("# empty", [], identifier="~/.aws/credentials") == Sensitivity.CONFIDENTIAL
    assert classify_sensitivity("", [], identifier="https://github.com/o/r/blob/main/.env") == Sensitivity.CONFIDENTIAL
    assert classify_sensitivity("ok", [], identifier="https://api.example.com/v1?api_key=abc") == Sensitivity.CONFIDENTIAL


def test_secret_inside_identifier_is_secret():
    assert classify_sensitivity("", [], identifier=f"https://{_gh()}@github.com/o/r.git") == Sensitivity.SECRET


@pytest.mark.parametrize(
    "text",
    [
        "card on file: 4111 1111 1111 1111",
        "amex 3782-822463-10005",
        "IBAN DE89 3704 0044 0532 0130 00",
        "Employee SSN: 123-45-6789",
        "\n".join(f"user{i}@acme-corp.io" for i in range(6)),
    ],
)
def test_pii_raises_sensitivity_to_confidential(text):
    assert classify_sensitivity(text, []) == Sensitivity.CONFIDENTIAL


@pytest.mark.parametrize(
    "text",
    [
        "order 4111 1111 1111 1112 failed",  # fails Luhn
        "timestamp 1731234567890123",  # no issuer prefix
        "contact alice@acme-corp.io or bob@acme-corp.io",  # not bulk
        "ref XX12 3456 7890 1234",  # unknown IBAN country
        "build 123-45-6789 passed",  # SSN shape without SSN wording
    ],
)
def test_pii_lookalikes_stay_internal(text):
    assert classify_sensitivity(text, []) == Sensitivity.INTERNAL


def test_public_urls_internal_hosts_and_default():
    assert classify_sensitivity("docs", [], identifier="https://docs.python.org/3/library/re.html") == Sensitivity.PUBLIC
    for host in ("http://localhost:8000/x", "http://10.0.0.5/a", "https://wiki.corp/x", "http://intranet/home",
                 "http://[::1]/", "https://svc.default.svc.cluster.local/"):
        assert classify_sensitivity("docs", [], identifier=host) == Sensitivity.INTERNAL, host
    assert classify_sensitivity("hello", []) == Sensitivity.INTERNAL
    assert classify_sensitivity("hello", [], identifier="src/main.py") == Sensitivity.INTERNAL


def test_previously_redacted_content_is_not_downgraded():
    assert classify_sensitivity("token [REDACTED:github_token:0a1b2c3d]", []) == Sensitivity.CONFIDENTIAL
