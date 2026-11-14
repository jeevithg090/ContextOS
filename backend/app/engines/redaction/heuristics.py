"""Value heuristics shared by the secret detectors.

These answer "does this candidate value look like a real credential?" without any context:
Shannon entropy, character-class mix, documentation placeholders (``your-api-key``, ``xxxx``,
``${VAR}``, ``<token>``) and code references (``os.environ["X"]``, ``self.token``, ``SecretStr``).
"""

from __future__ import annotations

import math
import re
from collections import Counter

# Exact (case-insensitive) values that are never real credentials.
_PLACEHOLDER_VALUES = frozenset(
    {
        "changeme",
        "change_me",
        "change-me",
        "changeit",
        "password",
        "passwd",
        "passw0rd",
        "pass",
        "secret",
        "secrets",
        "token",
        "apikey",
        "api_key",
        "api-key",
        "key",
        "none",
        "null",
        "nil",
        "undefined",
        "true",
        "false",
        "yes",
        "no",
        "on",
        "off",
        "empty",
        "required",
        "optional",
        "string",
        "str",
        "int",
        "bool",
        "bytes",
        "any",
        "secretstr",
        "secretbytes",
        "value",
        "values",
        "todo",
        "tbd",
        "fixme",
        "redacted",
        "hidden",
        "masked",
        "notset",
        "not_set",
        "unset",
        "default",
        "test",
        "testing",
        "example",
        "sample",
        "dummy",
        "fake",
        "placeholder",
        "mysecret",
        "mypassword",
        "mytoken",
        "myapikey",
        "foo",
        "bar",
        "baz",
        "foobar",
        "qwerty",
        "letmein",
        "admin",
        "root",
        "user",
        "username",
        "guest",
        "env",
        "environ",
        "process.env",
        "os.environ",
        "getenv",
        "os.getenv",
        "vault",
        "sops",
        "kms",
        "encrypted",
        "unknown",
        "n/a",
        "na",
    }
)

# Substrings that mark documentation / template values (checked on the lowercased value).
_PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "redacted",
    "dummy",
    "changeme",
    "change_me",
    "change-me",
    "replace_me",
    "replace-me",
    "replaceme",
    "replace_with",
    "replace-with",
    "insert_",
    "insert-",
    "enter_your",
    "enter-your",
    "not_a_real",
    "not-a-real",
    "notreal",
    "not_real",
    "fake_",
    "fake-",
    "sample_",
    "sample-",
    "xxxx",
    "****",
    "...",
    "…",
    "<your",
    "<insert",
    "{your",
)

_PLACEHOLDER_RE = re.compile(
    "|".join(
        (
            r"^(.)\1+$",  # one repeated character
            r"^(?i:[*x\u2022.#_\-?0]+)$",  # masks / fill characters
            r"^<[^<>]*>$",  # <token>
            r"^\[[^\[\]]*\]$",  # [api key]
            r"^(?s:\{\{.*\}\})$",  # {{ secret }}
            r"^(?s:\$\{.*\})$",  # ${VAR}
            r"^(?s:\$\(.*\))$",  # $(command)
            r"^\$[A-Za-z_][A-Za-z0-9_]*$",  # $VAR
            r"^%[A-Za-z_][A-Za-z0-9_]*%$",  # %VAR%
            r"^\{[A-Za-z_][A-Za-z0-9_]*\}$",  # {name}
            r"^@[A-Za-z_][A-Za-z0-9_]*@$",  # @VAR@
            r"^__[A-Z0-9_]+__$",  # __SECRET__
            r"^%[sdr]$|%\([a-z_]+\)s",  # printf templates
        )
    )
)
_MARKER_RE = re.compile("|".join(re.escape(marker) for marker in _PLACEHOLDER_MARKERS))
_YOUR_RE = re.compile(r"your.{0,12}(?:key|token|secret|pass|api|id|value|credential)", re.IGNORECASE)
_SEQUENTIAL_RE = re.compile(r"0123456789|123456789|abcdefghij|qwertyuiop", re.IGNORECASE)

# Code references that look like assignment values but are not literals.
_DOTTED_REF_RE = re.compile(r"^[A-Za-z_$][A-Za-z_$]*[0-9]{0,3}(?:\.[A-Za-z_$][A-Za-z_$]*[0-9]{0,3})+$")
_SNAKE_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")
_UPPER_SNAKE_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
_LETTERS_RE = re.compile(r"^[A-Za-z]+$")
_WORD_RE = re.compile(r"^[A-Z]?[a-z]+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DIGITS_RE = re.compile(r"^\d+$")
_PATH_VALUE_RE = re.compile(r"^(?:~|\.{1,2}|\$HOME|%[A-Za-z]+%)?[/\\][\w.\-/\\ ]*$|^[A-Za-z]:[\\/]")


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character (0 for empty strings)."""
    if not value:
        return 0.0
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in Counter(value).values())


def char_class_count(value: str) -> int:
    """How many of {lowercase, uppercase, digit, other} classes the value uses."""
    lower = upper = digit = other = False
    for ch in value:
        if ch.islower():
            lower = True
        elif ch.isupper():
            upper = True
        elif ch.isdigit():
            digit = True
        else:
            other = True
    return lower + upper + digit + other


def is_placeholder(value: str) -> bool:
    """True for documentation placeholders, masks and template variables (never real secrets)."""
    v = value.strip().strip("\"'`")
    if not v:
        return True
    low = v.lower()
    if low in _PLACEHOLDER_VALUES or _MARKER_RE.search(low) or _YOUR_RE.search(low):
        return True
    return _PLACEHOLDER_RE.search(v) is not None


def looks_fake(value: str) -> bool:
    """Values with keyboard/sequence runs are probably fabricated test fixtures."""
    return bool(_SEQUENTIAL_RE.search(value)) or len(set(value)) < max(4, len(value) // 6)


def is_code_reference(value: str) -> bool:
    """True when an unquoted assignment value is an identifier/expression rather than a literal."""
    v = value.strip()
    if not v:
        return True
    if v[0] in "$%!&*@" or v.startswith(("{{", "${")):
        return True  # shell/template variables, YAML tags/anchors, decorators
    if _DOTTED_REF_RE.match(v):
        return True  # self.token, settings.API_KEY, os.environ
    return bool(_SNAKE_RE.match(v) or _UPPER_SNAKE_RE.match(v) or _LETTERS_RE.match(v))


def is_word_like(value: str) -> bool:
    """A single lowercase or Capitalised word (UI labels such as "Password", "Passwort")."""
    return bool(_WORD_RE.match(value))


def is_hex(value: str) -> bool:
    return bool(_HEX_RE.match(value))


def is_digits(value: str) -> bool:
    return bool(_DIGITS_RE.match(value))


def is_path_value(value: str) -> bool:
    """A filesystem path (``~/.ssh/id_rsa``, ``/run/secrets/db``) rather than a secret value."""
    return bool(_PATH_VALUE_RE.match(value))


def token_strength(value: str) -> tuple[float, int]:
    """(entropy, character-class count) — the two numbers every gate uses."""
    return shannon_entropy(value), char_class_count(value)
