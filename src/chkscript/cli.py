from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import NoReturn

from chkscript.analyzer import AnalysisError, analyze
from chkscript.config import (
    DEFAULT_HOSTED_MODEL,
    DEFAULT_LOCAL_MODEL,
    ConfigError,
    load_config,
)
from chkscript.formatter import format_json, format_terminal
from chkscript.models import AnalysisResult, ScriptBundle
from chkscript.preprocess import ScriptTooLargeError, preprocess
from chkscript.static import StaticResult, run_static
from chkscript.static.merge import merge

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
            "Model to use (default: $CHKSCRIPT_MODEL, else "
            f"{DEFAULT_HOSTED_MODEL} when ANTHROPIC_API_KEY is set, "
            f"else {DEFAULT_LOCAL_MODEL})"
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


def main() -> None:
    _configure_logging()
    parser = _build_parser()
    args = parser.parse_args()

    try:
        settings = load_config(model=args.model)
    except ConfigError as e:
        _error(str(e))

    if not args.static_only and not os.environ.get("ANTHROPIC_API_KEY"):
        _error(
            "ANTHROPIC_API_KEY not set.\n" "  export ANTHROPIC_API_KEY='your-key-here'"
        )

    raw = _read_script(args.file)

    if not raw.strip():
        _error("Empty script provided")

    try:
        bundle = preprocess(raw)
    except ScriptTooLargeError as e:
        _error(str(e))

    static = _run_static(bundle)

    if args.static_only:
        result = AnalysisResult(
            summary="Static analysis only.",
            findings=static.findings,
            mode="static-only",
            static_tools=static.tools,
        )
    else:
        try:
            llm = analyze(bundle.text, model=settings.model)
        except AnalysisError as e:
            _error(str(e))
        except KeyboardInterrupt:
            sys.exit(3)
        # The model's findings go on top of the static floor; merge only raises.
        result = llm.model_copy(
            update={
                "findings": merge([*static.findings, *llm.findings]),
                "mode": "full",
                "static_tools": static.tools,
            }
        )

    if args.json_output:
        print(format_json(result))
    else:
        print(format_terminal(result, verbose=args.verbose))

    sys.exit(result.max_severity.value)
