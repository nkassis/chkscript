from __future__ import annotations

import json

import pytest
from pytest_mock import MockerFixture

from chkscript.analyzer import _parse_response, analyze
from chkscript.models import Severity


class TestParseResponse:
    def test_parse_clean_json(self) -> None:
        raw = json.dumps(
            {
                "summary": "Simple echo script",
                "findings": [],
                "notes": ["No issues found"],
            }
        )
        result = _parse_response(raw)
        assert result.summary == "Simple echo script"
        assert result.findings == []
        assert result.notes == ["No issues found"]
        assert result.max_severity == Severity.SAFE

    def test_parse_with_markdown_fencing(self) -> None:
        raw = '```json\n{"summary": "test", "findings": [], "notes": []}\n```'
        result = _parse_response(raw)
        assert result.summary == "test"

    def test_parse_unsafe_finding(self) -> None:
        raw = json.dumps(
            {
                "summary": "Dangerous script",
                "findings": [
                    {
                        "severity": "unsafe",
                        "description": "Pipes curl to bash",
                        "line_reference": "line 2",
                        "snippet": "curl ... | bash",
                    }
                ],
                "notes": [],
            }
        )
        result = _parse_response(raw)
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.UNSAFE
        assert result.findings[0].line_reference == "line 2"
        assert result.max_severity == Severity.UNSAFE

    def test_parse_warning_finding(self) -> None:
        raw = json.dumps(
            {
                "summary": "Script with warnings",
                "findings": [
                    {
                        "severity": "warning",
                        "description": "Unquoted variable",
                        "line_reference": "line 3",
                        "snippet": "echo $VAR",
                    }
                ],
                "notes": [],
            }
        )
        result = _parse_response(raw)
        assert result.findings[0].severity == Severity.WARNING
        assert result.max_severity == Severity.WARNING

    def test_parse_mixed_findings(self) -> None:
        raw = json.dumps(
            {
                "summary": "Mixed",
                "findings": [
                    {"severity": "warning", "description": "w1"},
                    {"severity": "unsafe", "description": "u1"},
                ],
                "notes": [],
            }
        )
        result = _parse_response(raw)
        assert result.max_severity == Severity.UNSAFE

    def test_parse_invalid_json_raises(self) -> None:
        with pytest.raises(json.JSONDecodeError):
            _parse_response("not json at all")

    def test_parse_optional_fields(self) -> None:
        raw = json.dumps(
            {
                "summary": "test",
                "findings": [{"severity": "warning", "description": "no extras"}],
            }
        )
        result = _parse_response(raw)
        assert result.findings[0].line_reference is None
        assert result.findings[0].snippet is None
        assert result.notes == []

    def test_unknown_severity_maps_to_warning(self) -> None:
        raw = json.dumps(
            {
                "summary": "Script with unknown severity",
                "findings": [
                    {
                        "severity": "critical",
                        "description": "Unknown severity level",
                    }
                ],
                "notes": [],
            }
        )
        result = _parse_response(raw)
        assert result.findings[0].severity == Severity.WARNING
        assert result.max_severity == Severity.WARNING


class TestAnalyze:
    def test_api_call(self, mocker: MockerFixture) -> None:
        mock_response = mocker.Mock()
        mock_response.content = [
            mocker.Mock(
                text=json.dumps(
                    {
                        "summary": "Hello script",
                        "findings": [],
                        "notes": [],
                    }
                )
            )
        ]
        mock_client = mocker.Mock()
        mock_client.messages.create.return_value = mock_response
        mocker.patch("chkscript.analyzer.anthropic.Anthropic", return_value=mock_client)

        result = analyze("#!/bin/bash\necho hello")
        assert result.summary == "Hello script"
        mock_client.messages.create.assert_called_once()

    def test_retry_on_parse_failure(self, mocker: MockerFixture) -> None:
        good_response = mocker.Mock()
        good_response.content = [
            mocker.Mock(
                text=json.dumps(
                    {
                        "summary": "Retry worked",
                        "findings": [],
                        "notes": [],
                    }
                )
            )
        ]
        bad_response = mocker.Mock()
        bad_response.content = [mocker.Mock(text="not json")]

        mock_client = mocker.Mock()
        mock_client.messages.create.side_effect = [bad_response, good_response]
        mocker.patch("chkscript.analyzer.anthropic.Anthropic", return_value=mock_client)

        result = analyze("#!/bin/bash\necho hello")
        assert result.summary == "Retry worked"
        assert mock_client.messages.create.call_count == 2
