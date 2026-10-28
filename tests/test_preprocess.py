from __future__ import annotations

import hashlib

import pytest

from chkscript.models import ExtractedUrl
from chkscript.preprocess import (
    MAX_SCRIPT_SIZE,
    ScriptTooLargeError,
    extract_urls,
    number_lines,
    preprocess,
)


class TestPreprocess:
    def test_size_limit_rejects_oversized_script(self) -> None:
        with pytest.raises(ScriptTooLargeError):
            preprocess(b"x" * (MAX_SCRIPT_SIZE + 1))

    def test_size_limit_accepts_script_at_limit(self) -> None:
        assert preprocess(b"x" * MAX_SCRIPT_SIZE).size == MAX_SCRIPT_SIZE

    def test_invalid_utf8_is_replaced_not_rejected(self) -> None:
        bundle = preprocess(b"echo \xff\xfe hi\n")
        assert bundle.text == "echo �� hi\n"

    def test_line_endings_normalized(self) -> None:
        bundle = preprocess(b"a\r\nb\rc\n")
        assert bundle.text == "a\nb\nc\n"

    def test_sha256_is_of_raw_bytes(self) -> None:
        raw = b"echo hi\r\n"
        assert preprocess(raw).sha256 == hashlib.sha256(raw).hexdigest()

    def test_line_text(self) -> None:
        bundle = preprocess(b"one\ntwo\n")
        assert bundle.line_text(2) == "two"
        assert bundle.line_text(0) is None
        assert bundle.line_text(99) is None


class TestNumberLines:
    def test_format(self) -> None:
        assert number_lines("echo a\ncurl x\n") == "   1 | echo a\n   2 | curl x"

    def test_width_grows_past_9999_lines(self) -> None:
        numbered = number_lines("x\n" * 10000).split("\n")
        assert numbered[0] == "    1 | x"
        assert numbered[-1] == "10000 | x"


class TestExtractUrls:
    def test_literal_url(self) -> None:
        urls = extract_urls("curl -fsSL https://get.example.com/install.sh | sh\n")
        assert urls == [
            ExtractedUrl(
                url="https://get.example.com/install.sh", line=1, kind="literal"
            )
        ]

    def test_quoted_url_and_http(self) -> None:
        urls = extract_urls('echo start\nwget "http://example.com/a.tgz"\n')
        assert urls == [
            ExtractedUrl(url="http://example.com/a.tgz", line=2, kind="literal")
        ]

    def test_url_with_variable_is_variable_built(self) -> None:
        urls = extract_urls('curl -o x "https://github.com/${REPO}/releases/$TAG"\n')
        assert urls == [
            ExtractedUrl(
                url="https://github.com/${REPO}/releases/$TAG", line=1, kind="variable"
            )
        ]

    def test_assignment_feeding_curl(self) -> None:
        script = 'DOWNLOAD_URL="$BASE/releases/$TAG/tool"\ncurl -o t "$DOWNLOAD_URL"\n'
        assert extract_urls(script) == [
            ExtractedUrl(url="$BASE/releases/$TAG/tool", line=1, kind="variable")
        ]

    def test_assignment_feeding_git_clone_braced(self) -> None:
        script = 'export repo="$HOST/org/repo.git"\ngit clone "${repo}" dest\n'
        assert extract_urls(script) == [
            ExtractedUrl(url="$HOST/org/repo.git", line=1, kind="variable")
        ]

    def test_assignment_not_feeding_a_fetcher_is_ignored(self) -> None:
        assert extract_urls('PREFIX="$HOME/.local"\necho "$PREFIX"\n') == []

    def test_assignment_with_literal_url_recorded_once(self) -> None:
        script = 'url="https://x.example/t"\ncurl -o t "$url"\n'
        assert extract_urls(script) == [
            ExtractedUrl(url="https://x.example/t", line=1, kind="literal")
        ]

    def test_bundle_carries_urls(self) -> None:
        bundle = preprocess(b"curl https://a.example/x\ncurl https://b.example/y\n")
        assert [(u.url, u.line) for u in bundle.urls] == [
            ("https://a.example/x", 1),
            ("https://b.example/y", 2),
        ]
