"""Trust engine: identifier canonicalisation and domain helpers."""

from __future__ import annotations

import pytest

from app.engines.trust import canonicalize_source, registrable_domain
from app.engines.trust.domains import parse_ip


@pytest.mark.parametrize(
    ("identifier", "expected"),
    [
        ("HTTPS://Docs.Example.com:443/a/./b/?utm_source=x#top", "https://docs.example.com/a/b"),
        ("http://example.com:80/", "http://example.com"),
        ("https://example.com:8443/x", "https://example.com:8443/x"),
        ("https://example.com/docs/", "https://example.com/docs"),
        ("https://example.com/a//b/../c", "https://example.com/a/c"),
        ("https://example.com/?utm_medium=e&id=7&fbclid=abc&gclid=z", "https://example.com?id=7"),
        ("https://example.com.", "https://example.com"),
    ],
)
def test_url_canonicalisation(identifier: str, expected: str) -> None:
    assert canonicalize_source("web", identifier)[0] == expected


def test_url_returns_registrable_domain() -> None:
    assert canonicalize_source("web", "https://a.b.docs.example.co.uk/x") == (
        "https://a.b.docs.example.co.uk/x",
        "example.co.uk",
    )


def test_url_credentials_are_never_kept() -> None:
    canonical, _ = canonicalize_source("web", "https://alice:hunter2@example.com/p?token=abc123&q=1")
    assert "hunter2" not in canonical and "alice" not in canonical and "abc123" not in canonical
    assert canonical == "https://example.com/p?token=REDACTED&q=1"


def test_presigned_signature_parameters_are_redacted() -> None:
    canonical, _ = canonicalize_source(
        "web", "https://bucket.s3.amazonaws.com/f.txt?X-Amz-Signature=deadbeef&X-Amz-Credential=AKIA123"
    )
    assert "deadbeef" not in canonical and "AKIA123" not in canonical


def test_database_url_drops_credentials() -> None:
    assert canonicalize_source("database", "postgres://u:secret@DB.acme.com:5432/prod") == (
        "postgres://db.acme.com:5432/prod",
        "acme.com",
    )


def test_idn_host_becomes_punycode() -> None:
    canonical, domain = canonicalize_source("web", "https://bücher.de/katalog")
    assert canonical == "https://xn--bcher-kva.de/katalog"
    assert domain == "xn--bcher-kva.de"


def test_fullwidth_host_is_normalised() -> None:
    assert canonicalize_source("web", "https://ｅｘａｍｐｌｅ。com/x")[0] == "https://example.com/x"


@pytest.mark.parametrize(
    ("source_type", "identifier", "expected"),
    [
        ("web", "https://GitHub.com/Acme/API/blob/Main/README.md?plain=1#L3", "github.com/acme/api/blob/Main/README.md"),
        ("web", "https://www.github.com/acme/api/", "github.com/acme/api"),
        ("web", "https://raw.githubusercontent.com/Acme/API/main/src/x.py", "github.com/acme/api/blob/main/src/x.py"),
        ("api", "https://api.github.com/repos/Acme/API/issues/1", "github.com/acme/api/issues/1"),
        ("repository", "git@github.com:Acme/API.git", "github.com/acme/api"),
        ("repository", "ssh://git@github.com/acme/api.git", "github.com/acme/api"),
        ("repository", "https://x-access-token:ghp_secret@github.com/acme/api.git", "github.com/acme/api"),
        ("repository", "Acme/API", "github.com/acme/api"),
        ("repository", "github.com/acme/api/tree/main/docs", "github.com/acme/api/tree/main/docs"),
        ("repository", "https://gitlab.com/Group/Sub/Proj/-/blob/main/X.md", "gitlab.com/group/sub/proj/-/blob/main/X.md"),
        ("repository", "https://git.acme.internal/Team/Repo.git", "git.acme.internal/Team/Repo"),
    ],
)
def test_repository_forms(source_type: str, identifier: str, expected: str) -> None:
    canonical, domain = canonicalize_source(source_type, identifier)
    assert canonical == expected
    assert "ghp_secret" not in canonical
    assert domain == registrable_domain(expected.split("/", 1)[0])


@pytest.mark.parametrize(
    ("source_type", "identifier", "expected"),
    [
        ("file", "/srv/app/../app/./config.yaml", "/srv/app/config.yaml"),
        ("file", "src//lib/./x.py", "src/lib/x.py"),
        ("file", "file:///etc/passwd", "/etc/passwd"),
        ("file", "C:\\Users\\me\\..\\notes.txt", "C:/Users/notes.txt"),
        ("repository", "/home/me/../me/repo/", "/home/me/repo"),
        ("document", "./docs/../README.md", "README.md"),
    ],
)
def test_file_paths_are_normalised_posix(source_type: str, identifier: str, expected: str) -> None:
    assert canonicalize_source(source_type, identifier) == (expected, None)


def test_file_path_case_is_preserved() -> None:
    assert canonicalize_source("file", "/Users/Me/Project/Main.PY")[0] == "/Users/Me/Project/Main.PY"


@pytest.mark.parametrize(
    ("source_type", "identifier", "expected"),
    [
        ("mcp_tool", "mcp__GitHub__create_issue", "github/create_issue"),
        ("mcp_tool", "Filesystem/Read_File", "filesystem/read_file"),
        ("mcp_tool", "slack:post_message", "slack/post_message"),
        ("mcp_server", "  GitHub ", "github"),
    ],
)
def test_mcp_names(source_type: str, identifier: str, expected: str) -> None:
    assert canonicalize_source(source_type, identifier) == (expected, None)


def test_remote_mcp_server_url_keeps_domain() -> None:
    assert canonicalize_source("mcp_server", "https://MCP.Example.com/sse") == (
        "https://mcp.example.com/sse",
        "example.com",
    )


@pytest.mark.parametrize(
    "identifier", ["Alice@Example.CO.UK", "Alice Smith <alice@example.co.uk>", "mailto:ALICE@example.co.uk?subject=hi"]
)
def test_email_forms(identifier: str) -> None:
    assert canonicalize_source("email", identifier) == ("alice@example.co.uk", "example.co.uk")


def test_bare_host_without_scheme_is_not_given_one() -> None:
    assert canonicalize_source("web", "Example.com/Docs/") == ("example.com/Docs", "example.com")


def test_prompts_and_tool_outputs_are_kept_verbatim() -> None:
    assert canonicalize_source("user_prompt", "  prompt-1 ") == ("prompt-1", None)
    assert canonicalize_source("tool_output", "WebFetch") == ("WebFetch", None)


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("www.example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("shop.example.com.au", "example.com.au"),
        ("x.y.example.co.jp", "example.co.jp"),
        ("alice.github.io", "alice.github.io"),
        ("docs.alice.github.io", "alice.github.io"),
        ("my-app.vercel.app", "my-app.vercel.app"),
        ("my-app.herokuapp.com", "my-app.herokuapp.com"),
        ("co.uk", "co.uk"),
        ("localhost", "localhost"),
        ("10.0.0.1", "10.0.0.1"),
    ],
)
def test_registrable_domain(host: str, expected: str) -> None:
    assert registrable_domain(host) == expected


@pytest.mark.parametrize(
    ("text", "expected", "nonstandard"),
    [
        ("127.0.0.1", "127.0.0.1", False),
        ("2130706433", "127.0.0.1", True),
        ("0x7f.0.0.1", "127.0.0.1", True),
        ("0177.0.0.1", "127.0.0.1", True),
        ("127.1", "127.0.0.1", True),
        ("[::1]", "::1", False),
        ("::ffff:169.254.169.254", "169.254.169.254", False),
    ],
)
def test_ip_parsing_including_obfuscated_forms(text: str, expected: str, nonstandard: bool) -> None:
    ip, odd = parse_ip(text)
    assert ip is not None and ip.compressed == expected
    assert odd is nonstandard


@pytest.mark.parametrize("text", ["example.com", "1.2.3.4.5", "256.1.1.1", "cafe", "0xzz.1"])
def test_non_ips_are_not_parsed_as_ips(text: str) -> None:
    assert parse_ip(text)[0] is None


def test_obfuscated_ip_url_is_canonicalised_to_dotted_quad() -> None:
    assert canonicalize_source("web", "http://2130706433/admin") == ("http://127.0.0.1/admin", "127.0.0.1")


def test_backslash_userinfo_trick_resolves_to_the_host_a_browser_would_use() -> None:
    # WHATWG URL parsing treats "\" as "/" in http(s) URLs, so the browser goes to evil.com.
    canonical, domain = canonicalize_source("web", "https://evil.com\\@good.com/")
    assert domain == "evil.com" and canonical.startswith("https://evil.com")
