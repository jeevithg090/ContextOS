"""AWS secret access keys written without their usual ``aws_secret_access_key =`` context.

A 40-character AWS-secret-shaped value is flagged only when the text makes an AWS secret likely
(an AWS anchor word nearby, before or after, or a standalone AKIA/ASIA key id anywhere in the same
text). Git SHAs, placeholders, longer base64 runs and wrapped base64 blocks stay unflagged.

Credentials are generated from a seeded RNG so no secret-shaped literal lives in the repository.
"""

from __future__ import annotations

import random
import string

import pytest

from app.engines.redaction import HIGH_CONFIDENCE, detect_secrets, redact_text

_RNG = random.Random(4011)
B64 = string.ascii_letters + string.digits + "+/"
UPPER = string.ascii_uppercase + string.digits
HEX = "0123456789abcdef"


def rnd(n: int, alphabet: str = B64) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(n))


def secret() -> str:
    """A 40-char AWS-secret-shaped value with lower, upper, digit and symbol classes."""
    return rnd(36) + "a/9Z"


def key_id(prefix: str = "AKIA") -> str:
    return prefix + rnd(16, UPPER)


def aws_secrets(text: str) -> list:
    return [m for m in detect_secrets(text) if m.secret_type == "aws_secret_key"]


@pytest.mark.parametrize(
    "template",
    [
        "aws={s}",  # "=" directly before the value used to defeat the boundary check
        "AWS='{s}'",
        "export aws_key={s}",
        "creds: aws {s}",
        "payload={s} # aws credential for the deploy role",  # anchor after the value
        '{{"SecretAccessKey": "{s}", "AccessKeyId": "{k}"}}',  # STS JSON, secret before the key id
        "payload={s}\nid {k}",
    ],
)
def test_aws_secret_found_with_nearby_context(template):
    s = secret()
    text = template.format(s=s, k=key_id())
    found = aws_secrets(text)
    assert len(found) == 1, (text, detect_secrets(text))
    assert text[found[0].start : found[0].end] == s
    assert found[0].confidence >= HIGH_CONFIDENCE
    assert s not in redact_text(text).text


def test_aws_secret_found_when_a_key_id_appears_anywhere_in_the_text():
    s = secret()
    filler = "\n".join(f"line {i}: build step completed without errors" for i in range(40))
    text = f"id {key_id('ASIA')}\n{filler}\npayload={s}\n"
    found = aws_secrets(text)
    assert len(found) == 1 and text[found[0].start : found[0].end] == s
    assert found[0].confidence >= HIGH_CONFIDENCE


@pytest.mark.parametrize(
    "template",
    [
        "payload={s}",  # no AWS context at all
        "x {s} y",
        "the token {s} was rotated",
    ],
)
def test_aws_shaped_value_without_context_is_not_flagged(template):
    assert aws_secrets(template.format(s=secret())) == []


def test_git_shas_and_hex_are_never_aws_secrets():
    text = f"aws deploy {key_id()} at commit {rnd(40, HEX)} (parent {rnd(40, HEX)})"
    assert aws_secrets(text) == []


def test_longer_base64_runs_and_padding_are_not_cut_into_secrets():
    text = f"aws blob={rnd(80)} and {key_id()} sig={rnd(39)}x=="
    assert aws_secrets(text) == []


def test_wrapped_base64_block_tail_is_not_flagged_by_a_distant_key_id():
    lines = [rnd(64) for _ in range(4)] + [rnd(36) + "a/9Z"]
    pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----"
    filler = "\n".join("unrelated log line" for _ in range(20))
    text = f"{key_id()}\n{filler}\n{pem}"
    assert aws_secrets(text) == []


def test_placeholders_and_low_entropy_values_stay_unflagged():
    for value in ("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "a" * 40, "abcd" * 10):
        assert aws_secrets(f"aws={value} {key_id()}") == [], value


def test_key_id_inside_an_embedded_image_does_not_enable_document_matching():
    image = "data:image/png;base64,iVBORw0KGgo" + "+" + key_id() + "/" + rnd(120)
    text = f"{image}\npayload={secret()}"
    assert aws_secrets(text) == []
