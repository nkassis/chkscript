from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
from typing import NoReturn

from chkscript.analyzer import (
    AnalysisError,
    FloorViolationError,
    LLMAnalyzer,
    merge_llm,
)
from chkscript.config import (
    DEFAULT_HOSTED_MODEL,
    DEFAULT_LOCAL_MODEL,
    NO_MODEL_NOTICE,
    ConfigError,
    load_config,
    resolve_model,
)
from chkscript.formatter import format_json, format_terminal
from chkscript.models import AnalysisResult, Finding, ScriptBundle, Severity
from chkscript.preprocess import ScriptTooLargeError, preprocess
from chkscript.static import StaticResult, run_static

logger = logging.getLogger("chkscript")


class _Parser(argparse.ArgumentParser):
    """argparse exits 2 on a usage error; in chkscript 2 means unsafe."""

    def error(self, message: str) -> NoReturn:
        logger.error("%s", self.format_usage().rstrip())
        _error(message)


def _build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="chkscript",
        description="Analyze shell scripts for safety issues",
    )
    parser.add_argument(
        "file",
        nargs="?",
        metavar="FILE",
        help="Script file to analyze (reads from stdin if omitted)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed output including all code snippets",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output as JSON",
    )
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="Run only the static layer (no model, no API key needed)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=(
            "provider:model selector (default: $CHKSCRIPT_MODEL, else "
            f"{DEFAULT_HOSTED_MODEL} when ANTHROPIC_API_KEY is set, else "
            f"{DEFAULT_LOCAL_MODEL} when Ollama answers, else static only)"
        ),
    )
    return parser


def _read_script(file_arg: str | None) -> bytes:
    # Raw bytes: decoding and line endings are preprocess.py's job.
    if file_arg:
        try:
            with open(file_arg, "rb") as f:
                return f.read()
        except FileNotFoundError:
            _error(f"File not found: {file_arg}")
        except PermissionError:
            _error(f"Permission denied: {file_arg}")
        except OSError as e:
            _error(f"Cannot read file: {e}")

    if not sys.stdin.isatty():
        return sys.stdin.buffer.read()

    _error(
        "No input. Provide a file argument or pipe a script via stdin.\n"
        "Usage: chkscript script.sh\n"
        "       curl -fsSL https://example.com/install.sh | chkscript"
    )


def _configure_logging() -> None:
    # Fresh handler per run so it binds to the current sys.stderr.
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.handlers[:] = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)


def _error(msg: str) -> NoReturn:
    logger.error("Error: %s", msg)
    sys.exit(3)


def _run_static(bundle: ScriptBundle) -> StaticResult:
    static = run_static(bundle)
    for notice in static.notices:
        logger.info("Notice: %s", notice)
    logger.info("Static tools: %s", ", ".join(static.tools))
    return static


def _static_report(static: StaticResult, extra: list[Finding]) -> AnalysisResult:
    return AnalysisResult(
        summary="Static analysis only.",
        findings=[*static.findings, *extra],
        mode="static-only",
        static_tools=static.tools,
    )


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _announce_endpoint(analyzer: LLMAnalyzer) -> None:
    host = analyzer.endpoint_host
    if host is not None and not _is_loopback(host):
        logger.info("Script contents will be sent to %s for analysis.", host)


def _llm_not_run(static: StaticResult, reason: str) -> AnalysisResult:
    logger.warning("Warning: the LLM layer did not run (%s).", reason)
    notice = Finding(
        severity=Severity.WARNING,
        category="lint",
        description=(
            f"The LLM layer did not run ({reason}); this report is static "
            "analysis only."
        ),
        source="chkscript",
        rule_id="llm-not-run",
    )
    return _static_report(static, [notice])


def _run_llm(bundle: ScriptBundle, static: StaticResult, model: str) -> AnalysisResult:
    try:
        analyzer = LLMAnalyzer(model)
        _announce_endpoint(analyzer)
        llm = analyzer.analyze(bundle, static.findings)
    except AnalysisError as e:
        return _llm_not_run(static, str(e))
    try:
        findings = merge_llm(static.findings, llm, bundle)
    except FloorViolationError as e:
        _error(f"internal error, refusing to report: {e}")
    return AnalysisResult(
        summary=llm.summary,
        findings=findings,
        notes=llm.notes,
        mode="full",
        static_tools=static.tools,
    )


def main() -> None:
    _configure_logging()
    # An uncaught exception would exit 1, which reads as "warnings only".
    try:
        _run()
    except KeyboardInterrupt:
        sys.exit(3)
    except Exception as e:
        # The type only: an arbitrary message may span lines or echo input.
        _error(f"Unexpected error ({type(e).__name__})")


def _run() -> NoReturn:
    parser = _build_parser()
    args = parser.parse_args()

    try:
        settings = load_config(model=args.model)
    except ConfigError as e:
        _error(str(e))

    raw = _read_script(args.file)

    if not raw.strip():
        _error("Empty script provided")

    try:
        bundle = preprocess(raw)
    except ScriptTooLargeError as e:
        _error(str(e))

    static = _run_static(bundle)

    model = None if args.static_only else resolve_model(settings)
    if model is None:
        if not args.static_only:
            logger.info("Notice: %s", NO_MODEL_NOTICE)
        result = _static_report(static, [])
    else:
        result = _run_llm(bundle, static, model)

    if args.json_output:
        print(format_json(result))
    else:
        print(format_terminal(result, verbose=args.verbose))

    sys.exit(result.max_severity.value)
