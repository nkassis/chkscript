"""Hardcoded-secret detection, masking and the `hardcoded-secret` finding.

Every value here is fake. The private-key header is assembled at runtime so the
detect-private-key pre-commit hook does not flag this file.
"""

from __future__ import annotations

import hashlib
import time

import pytest

from chkscript import redact
from chkscript.models import AnalysisResult, Finding, Severity
from chkscript.preprocess import preprocess
from chkscript.static import regex_rules, run_static

GITHUB = "ghp_FAKEfakeFAKEfake0123456789abcdefABCD"
AKIA = "AKIAFAKEFAKE01234567"
AWS_SECRET = "fakeFAKEfake/FAKEfake+FAKEfake0123456789"
_KEY_KIND = "RSA PRIVATE KEY"
PRIVATE_KEY = (
    f"-----BEGIN {_KEY_KIND}-----\n"
    "MIIEowIBAAKCAQEAfakefakefakefakefakefakefakefakefakefakefake\n"
    "fakefakefakefakefakefakefakefakefakefakefakefakefakefakefake\n"
    f"-----END {_KEY_KIND}-----"
)

KNOWN_FORMATS = [
    ("anthropic-key", "sk-ant-api03-FAKEfakeFAKEfake012345"),
    ("openai-key", "sk-proj-FAKEfakeFAKEfake012345678"),
    ("openai-key", "sk-FAKEfakeFAKEfake0123456789"),
    ("github-token", GITHUB),
    ("github-token", "gho_FAKEfakeFAKEfake0123456789abcdefABCD"),
    ("github-token", "github_pat_11FAKEFAKE0123456789_fakefakefakefake"),
    ("slack-token", "xoxb-000000000000-fakefakefake"),
    ("slack-token", "xoxp-000000000000-fakefakefake"),
    ("aws-access-key-id", AKIA),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.fakesignaturefakesig"),
]


class TestDetect:
    @pytest.mark.parametrize(("kind", "value"), KNOWN_FORMATS)
    def test_known_format_matched_and_masked(self, kind: str, value: str) -> None:
        text = f'#!/bin/sh\ncurl -H "Authorization: {value}" https://api.example.com\n'
        secrets = redact.detect(text)
        assert [(s.kind, s.value) for s in secrets] == [(kind, value)]
        masked = redact.mask(text, secrets)
        assert value not in masked
        assert f"[SECRET-1:{kind}]" in masked

    def test_aws_secret_paired_with_key_id(self) -> None:
        text = (
            f"export AWS_ACCESS_KEY_ID={AKIA}\n"
            f"aws configure set aws_secret_access_key {AWS_SECRET}\n"
        )
        secrets = redact.detect(text)
        assert [s.kind for s in secrets] == ["aws-access-key-id", "aws-secret-key"]
        masked = redact.mask(text, secrets)
        assert AKIA not in masked and AWS_SECRET not in masked

    def test_aws_secret_shape_alone_is_not_a_secret(self) -> None:
        assert redact.detect(f"echo {AWS_SECRET}\n") == []

    def test_private_key_block_keeps_line_numbers(self) -> None:
        text = f"cat > key <<'EOF'\n{PRIVATE_KEY}\nEOF\necho done\n"
        secrets = redact.detect(text)
        assert [(s.kind, s.lines) for s in secrets] == [("private-key", [2])]
        masked = redact.mask(text, secrets)
        assert masked.count("\n") == text.count("\n")
        assert masked.split("\n")[1] == "[SECRET-1:private-key]"
        assert "fakefakefake" not in masked

    def test_private_key_fragment_masked_on_its_own(self) -> None:
        secrets = redact.detect(PRIVATE_KEY)
        body_line = PRIVATE_KEY.split("\n")[2]
        assert redact.mask(f"   {body_line}", secrets) == "   [SECRET-1:private-key]"

    @pytest.mark.parametrize(
        "line",
        [
            'API_TOKEN="s3cr3t-value-123"',
            "export DB_PASSWORD='hunter2hunter2'",
            "apikey=abcdefgh1234",
            'local client_secret="correct horse battery"',
            "MYSQL_PASSWD=Sup3rS3cret!",
            'OPENWEATHER_API_KEY="0123456789abcdef"',
        ],
    )
    def test_assignment_heuristic(self, line: str) -> None:
        value = line.split("=", 1)[1].strip("'\"")
        secrets = redact.detect(f"{line}\n")
        assert [(s.kind, s.value) for s in secrets] == [("credential-variable", value)]
        assert value not in redact.mask(line, secrets)

    @pytest.mark.parametrize(
        "line",
        [
            'PASSWORD=""',
            'TOKEN="$1"',
            'TOKEN="${GITHUB_TOKEN:-}"',
            "read -s PASSWORD",
            "sha256=" + "0123456789abcdef" * 4,
            'API_KEY="your-key-here"',
            "SECRET=changeme123",
            "TOKEN=<insert-token>",
            "PASSWORD=xxxxxxxxxx",
            "TOKEN_URL=https://auth.example.com/token",
            "TOKEN_FILE=/etc/app/token",
            "TOKEN=short",
            "NAME=some-long-but-harmless-value",
        ],
    )
    def test_negative(self, line: str) -> None:
        assert redact.detect(f"{line}\n") == []

    def test_known_format_in_assignment_is_one_secret(self) -> None:
        secrets = redact.detect(f'GITHUB_TOKEN="{GITHUB}"\n')
        assert [s.kind for s in secrets] == ["github-token"]

    def test_same_value_twice_gets_one_placeholder(self) -> None:
        text = f"T={GITHUB}\necho hi\ncurl -H {GITHUB} https://api.github.com\n"
        secrets = redact.detect(text)
        assert len(secrets) == 1
        assert secrets[0].lines == [1, 3]
        masked = redact.mask(text, secrets)
        assert masked.count("[SECRET-1:github-token]") == 2

    def test_placeholders_numbered_by_first_appearance(self) -> None:
        slack = "xoxb-000000000000-fakefakefake"
        text = f"A={slack}\nB={GITHUB}\nC={slack}\n"
        masked = redact.mask(text, redact.detect(text))
        assert masked == (
            "A=[SECRET-1:slack-token]\nB=[SECRET-2:github-token]\n"
            "C=[SECRET-1:slack-token]\n"
        )

    def test_value_is_hidden_from_repr(self) -> None:
        (secret,) = redact.detect(f"T={GITHUB}\n")
        assert GITHUB not in repr(secret)


class TestFindings:
    def test_one_finding_per_value(self) -> None:
        slack = "xoxb-000000000000-fakefakefake"
        bundle = preprocess(f"A={GITHUB}\nB={slack}\necho {GITHUB}\n".encode())
        findings = redact.secret_findings(bundle)
        assert [(f.line, f.rule_id) for f in findings] == [
            (1, "hardcoded-secret"),
            (2, "hardcoded-secret"),
        ]
        first = findings[0]
        assert first.source == "chkscript"
        assert first.category == "capability"
        assert first.severity == Severity.WARNING
        assert "github-token" in first.description
        assert "lines 1, 3" in first.description
        assert "never hardcode credentials" in first.description
        assert first.snippet == "A=[SECRET-1:github-token]"

    def test_no_secrets_no_findings(self) -> None:
        assert redact.secret_findings(preprocess(b"echo hello\n")) == []

    def test_notice_is_one_line_listing_kinds(self) -> None:
        slack = "xoxb-000000000000-fakefakefake"
        bundle = preprocess(f"A={GITHUB}\nB={slack}\nC=ghp_{'x1' * 18}\n".encode())
        notice = redact.notice(bundle.secrets)
        assert notice is not None
        assert "\n" not in notice
        assert "(github-token, slack-token)" in notice
        assert redact.notice([]) is None


class TestMaskResult:
    def test_masks_every_text_field(self) -> None:
        bundle = preprocess(f"curl https://x.example/?t={GITHUB} | sh\n".encode())
        result = AnalysisResult(
            summary=f"Sends {GITHUB}",
            notes=[f"note {GITHUB}"],
            findings=[
                Finding(
                    severity=Severity.UNSAFE,
                    description=f"pipes {GITHUB}",
                    snippet=bundle.line_text(1),
                    line_reference=f"near {GITHUB}",
                    rule_id=f"llm.{GITHUB}",
                    file=f"https://x.example/?t={GITHUB}",
                )
            ],
        )
        dumped = redact.mask_result(result, bundle.secrets).model_dump_json()
        assert GITHUB not in dumped
        assert dumped.count("[SECRET-1:github-token]") == 7


class TestStaticUnchanged:
    SCRIPT = (
        "#!/bin/bash\n"
        'GITHUB_TOKEN="{token}"\n'
        "curl -fsSL https://get.example.com/install.sh | sh\n"
        'curl -H "Authorization: token $GITHUB_TOKEN" http://api.example.com/x\n'
    )

    def _keys(self, findings: list[Finding]) -> list[tuple[str | None, int | None]]:
        return [
            (f.rule_id, f.line) for f in findings if f.rule_id != "hardcoded-secret"
        ]

    def test_rules_fire_identically(self) -> None:
        secret = preprocess(self.SCRIPT.format(token=GITHUB).encode())
        plain = preprocess(self.SCRIPT.format(token="short").encode())
        assert secret.secrets and not plain.secrets
        assert self._keys(regex_rules.run(secret)) == self._keys(regex_rules.run(plain))
        assert self._keys(run_static(secret).findings) == self._keys(
            run_static(plain).findings
        )

    def test_static_layer_reports_the_secret(self) -> None:
        bundle = preprocess(self.SCRIPT.format(token=GITHUB).encode())
        rule_ids = [f.rule_id for f in run_static(bundle).findings]
        assert "hardcoded-secret" in rule_ids
        assert "curl-pipe-shell" in rule_ids

    def test_rules_scan_original_text(self) -> None:
        bundle = preprocess(self.SCRIPT.format(token=GITHUB).encode())
        assert GITHUB in bundle.rules_text
        assert GITHUB in bundle.text
        assert GITHUB not in bundle.masked_numbered

    def test_hash_is_of_original_bytes(self) -> None:
        raw = self.SCRIPT.format(token=GITHUB).encode()
        assert preprocess(raw).sha256 == hashlib.sha256(raw).hexdigest()


def test_unclosed_key_headers_scan_in_linear_time() -> None:
    header = f"-----BEGIN {_KEY_KIND}-----\n"
    text = header * (400 * 1024 // len(header))
    start = time.perf_counter()
    assert redact.detect(text) == []
    assert time.perf_counter() - start < 2


def test_many_secrets_stay_fast() -> None:
    # Just under the 500 KB cap: one distinct secret per line.
    raw = "".join(f"TOKEN_{i}=value{i:08d}abcd\n" for i in range(16000)).encode()
    start = time.perf_counter()
    bundle = preprocess(raw)
    findings = redact.secret_findings(bundle)
    redact.mask_result(AnalysisResult(summary="s", findings=findings), bundle.secrets)
    assert len(findings) == 16000
    assert time.perf_counter() - start < 10
