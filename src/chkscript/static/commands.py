"""Syntax tree to command model: the commands a script actually runs.

Built from shfmt's `--to-json` tree (static/shfmt.py). The rules in
static/rules/ read only this model, never the script text, so:

- Only executed commands appear. Heredoc bodies and quoted strings are data,
  unless they are fed to a shell (`sh <<EOF`, `bash -c '...'`), in which case
  they are parsed as code. The statements inside `$(...)` and `<(...)` run.
- Wrappers are stripped: `sudo`, `doas`, `env`, `command`, `exec`, `nohup`,
  and any function whose body uses its positional parameters, which is
  inlined at each call (`execute "${CHMOD[@]}" ...` becomes `chmod ...`).
- A variable or array whose every assignment in the file is a literal
  resolves to that set of values, at uses after its first assignment. Any
  other value is unknown, and rules judge unknown values as the dangerous case.
- A heredoc written to a file that is later run, installed or made executable
  becomes a generated child file, scanned as its own script.
- Every curl/wget records its URL and output path, so verification and
  execution can be judged per downloaded file.
"""

from __future__ import annotations

import itertools
import posixpath
import re
import sys
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, replace
from typing import Any

from chkscript.static.shfmt import ShfmtError

Node = dict[str, Any]
Parser = Callable[[str], Node]

SHELLS = frozenset({"sh", "bash", "zsh"})
DOWNLOADERS = frozenset({"curl", "wget"})
COPIERS = frozenset({"cp", "mv", "install", "ln"})
# Above this many alternative argv lists for one command, the words that
# multiply them collapse to unknown.
MAX_ALTERNATIVES = 8
# Above this many values, a word is unknown rather than a set.
MAX_VALUES = 16
MAX_EMBED_DEPTH = 4
MAX_INLINE_DEPTH = 6
_POSITIONAL = frozenset({"@", "*", "1", "2", "3", "4", "5", "6", "7", "8", "9"})
_IDENTIFIER = re.compile(r"[A-Za-z_]\w*")
_ASSIGN_WORD = re.compile(r"[A-Za-z_]\w*=")
_EVAL_ASSIGN = re.compile(r"(?:^|[\s;&|({])([A-Za-z_]\w*)(?:\[[^]]*\])?\+?=")
_ARITH_ASSIGN = frozenset(
    {"=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "|=", "^="}
)
_ARCHIVE_SUFFIXES = (
    ".tar.gz",
    ".tar.xz",
    ".tar.zst",
    ".tar.bz2",
    ".tgz",
    ".tar",
    ".zip",
    ".gz",
    ".xz",
    ".zst",
    ".bz2",
    ".sha256sum",
    ".sha256",
    ".sha512",
    ".asc",
    ".sig",
    ".minisig",
)
_NOT_A_PATH = frozenset({"", "-", ".", "/dev/null", "/dev/stdout", "/dev/stderr"})


# --- model -----------------------------------------------------------------


@dataclass(frozen=True)
class Arg:
    """One word of a command, as far as it can be known without running it.

    `text` is the word with quoting removed and every expansion kept as its
    source (`$HOME/.bashrc`, `$(uname -m)`); `values` is every string the word
    can be, or None when unknown. A `splat` stands for an unknown number of
    words, such as `"$@"` with unknown positional parameters. A `bare` word
    is a lone unquoted expansion (`$SUDO`): taken as one word, but in command
    position it may also be empty or a wrapper.
    """

    text: str
    values: frozenset[str] | None = None
    expanded: bool = False
    splat: bool = False
    bare: bool = False
    line: int | None = field(default=None, compare=False)

    @classmethod
    def lit(cls, value: str, line: int | None = None) -> Arg:
        return cls(value, frozenset({value}), line=line)

    @property
    def literal(self) -> str | None:
        """The word's single value, when it has exactly one."""
        if self.values is not None and len(self.values) == 1:
            return next(iter(self.values))
        return None

    def candidates(self) -> list[str]:
        """The values when known, else the text: what rules match against."""
        return sorted(self.values) if self.values is not None else [self.text]

    @property
    def is_flag(self) -> bool:
        # A constant's known value is a flag too (`FLAGS=-fsSL; curl $FLAGS`).
        value = self.literal if self.expanded else self.text
        return value is not None and value.startswith("-") and value != "-"


@dataclass(frozen=True)
class Redirect:
    op: str
    fd: str | None
    target: Arg | None
    # For `<<` and `<<-`: the body as the receiving command reads it.
    heredoc: str | None = None
    body_line: int | None = None
    quoted: bool = False

    @property
    def writes(self) -> bool:
        """An output redirect to a file (not `>&2`-style duplication)."""
        if self.target is None:
            return False
        if self.op in (">", ">>", ">|", "&>", "&>>"):
            return True
        return self.op == ">&" and not self.target.text.isdigit()

    @property
    def writes_stdout(self) -> bool:
        return self.writes and self.fd in (None, "1")


@dataclass
class Command:
    """One executed command, with wrappers stripped and words resolved."""

    argv: list[Arg]
    line: int
    file: str
    pos: int = 0
    index: int = 0
    as_root: bool = False
    function: str | None = None
    redirects: tuple[Redirect, ...] = ()
    pipeline: int | None = None
    stage: int = 0

    @property
    def name(self) -> str | None:
        """Basename of the command word when it is one known literal."""
        if not self.argv:
            return None
        word = self.argv[0].literal
        return posixpath.basename(word) if word else None

    @property
    def args(self) -> list[Arg]:
        return self.argv[1:]

    def heredocs(self) -> list[Redirect]:
        return [r for r in self.redirects if r.heredoc is not None]

    def stdin_code(self) -> list[tuple[str, int | None]]:
        """(text, first line) of what a heredoc or a `<<<` here-string feeds
        to this command's standard input."""
        out: list[tuple[str, int | None]] = []
        for r in self.redirects:
            if r.heredoc is not None:
                out.append((r.heredoc, r.body_line))
            elif r.op == "<<<" and r.target is not None:
                text = r.target.literal
                out.append((text if text is not None else r.target.text, r.target.line))
        return out


@dataclass(frozen=True)
class Download:
    command: Command
    urls: tuple[Arg, ...]
    # The file written; None when the output goes to stdout or is unknown.
    path: Arg | None

    @property
    def line(self) -> int:
        return self.command.line


@dataclass(frozen=True)
class GeneratedFile:
    """A heredoc written to a file the script later runs, installs or chmods."""

    path: Arg
    label: str
    text: str
    # The writing command's line, and the line of the body's first line, in
    # the parent file.
    line: int
    body_line: int
    file: str


@dataclass(frozen=True)
class Snippet:
    """Embedded code shfmt could not parse; the regex rules cover it."""

    text: str
    line: int
    file: str


@dataclass
class CommandModel:
    file: str
    commands: list[Command] = field(default_factory=list)
    downloads: list[Download] = field(default_factory=list)
    generated: list[GeneratedFile] = field(default_factory=list)
    unparsed: list[Snippet] = field(default_factory=list)

    def later_stages(self, command: Command) -> list[Command]:
        """Commands in later stages of `command`'s pipeline."""
        if command.pipeline is None:
            return []
        return [
            c
            for c in self.commands
            if c.pipeline == command.pipeline and c.stage > command.stage
        ]

    def named(self, *names: str) -> Iterator[Command]:
        return (c for c in self.commands if c.name in names)


# --- option parsing, shared with the rules ---------------------------------


@dataclass(frozen=True)
class Options:
    flags: tuple[tuple[str, Arg | None], ...]
    operands: tuple[Arg, ...]

    def has(self, *names: str) -> bool:
        return any(flag in names for flag, _ in self.flags)

    def value(self, *names: str) -> Arg | None:
        found = [value for flag, value in self.flags if flag in names]
        return found[-1] if found else None


def parse_options(
    args: Iterable[Arg],
    short_value: str = "",
    long_value: frozenset[str] = frozenset(),
) -> Options:
    """Split GNU-style arguments into flags and operands.

    Short clusters (`-fsSLo out`) are expanded; a letter in `short_value`
    takes the rest of the cluster or the next word as its value. `--opt=v`
    always carries its value; `--opt v` does for options in `long_value`.
    """
    flags: list[tuple[str, Arg | None]] = []
    operands: list[Arg] = []
    items = list(args)
    i = 0
    while i < len(items):
        arg = items[i]
        i += 1
        if arg.literal == "--" and not arg.expanded:
            operands.extend(items[i:])
            break
        if not arg.is_flag or arg.splat:
            operands.append(arg)
            continue
        text = arg.text
        if text.startswith("--"):
            name, eq, inline = text.partition("=")
            if eq:
                flags.append((name, Arg.lit(inline)))
            elif name in long_value and i < len(items):
                flags.append((name, items[i]))
                i += 1
            else:
                flags.append((name, None))
            continue
        for k, letter in enumerate(text[1:]):
            if letter in short_value:
                rest = text[2 + k :]
                if rest:
                    flags.append((f"-{letter}", Arg.lit(rest)))
                elif i < len(items):
                    flags.append((f"-{letter}", items[i]))
                    i += 1
                else:
                    flags.append((f"-{letter}", None))
                break
            flags.append((f"-{letter}", None))
    return Options(tuple(flags), tuple(operands))


_CHMOD_FLAGS = frozenset(
    {
        "-R",
        "-f",
        "-v",
        "-c",
        "-h",
        "-H",
        "-L",
        "-P",
        "--recursive",
        "--verbose",
        "--changes",
        "--silent",
        "--quiet",
        "--no-dereference",
        "--dereference",
        "--preserve-root",
        "--no-preserve-root",
    }
)
_EXEC_SYMBOLIC = re.compile(r"[ugoa]*\+[rwst]*x")
_OCTAL = re.compile(r"[0-7]{1,4}")


def chmod_parts(command: Command) -> tuple[Arg | None, list[Arg]]:
    """(mode, files) of a chmod. A mode like `-x` is a mode, not a flag."""
    args = command.args
    i = 0
    while i < len(args):
        text = args[i].literal
        if text in _CHMOD_FLAGS or (text or "").startswith("--reference="):
            i += 1
            continue
        if text == "--":
            i += 1
        break
    if i >= len(args) or args[i].splat:
        return None, list(args[i + 1 :])
    return args[i], list(args[i + 1 :])


def adds_execute(mode: Arg) -> bool:
    """A chmod mode that grants execute to anyone (`+x`, `u+rwx`, `755`)."""
    for value in mode.values or ():
        if _EXEC_SYMBOLIC.search(value):
            return True
        if _OCTAL.fullmatch(value) and any(d in "1357" for d in value):
            return True
    return False


def path_names(arg: Arg) -> set[str]:
    """Names under which a path can be referred to elsewhere in the script.

    The path itself, its basename, and both with an archive or checksum
    suffix removed: `$exe.zip` ties to `$exe`, `/tmp/t.sha256` to `t`.
    """
    names: set[str] = set()
    for candidate in arg.candidates():
        candidate = candidate.rstrip("/") if candidate != "/" else candidate
        if candidate in _NOT_A_PATH:
            continue
        for name in (candidate, posixpath.basename(candidate)):
            if name in _NOT_A_PATH:
                continue
            names.add(name)
            for suffix in _ARCHIVE_SUFFIXES:
                if name.endswith(suffix) and len(name) > len(suffix):
                    names.add(name[: -len(suffix)])
    return names


def tied(a: Arg, b: Arg) -> bool:
    return bool(path_names(a) & path_names(b))


# --- constants -------------------------------------------------------------


class _Constants:
    """Per variable: every assignment in the file, literal value or not."""

    def __init__(self) -> None:
        self._entries: dict[str, list[tuple[int, tuple[str, ...] | None]]] = {}

    def record(self, name: str, pos: int, value: tuple[str, ...] | None) -> None:
        self._entries.setdefault(name, []).append((pos, value))

    def assigns(self, name: str) -> bool:
        return name in self._entries

    def lookup(self, name: str, pos: int) -> list[tuple[str, ...]] | None:
        """The literal values of `name` at byte offset `pos`, or None.

        Unknown when any assignment is not a literal, when there is none, or
        when `pos` comes before the first one (the value could come from the
        environment).
        """
        entries = self._entries.get(name)
        if not entries or any(value is None for _, value in entries):
            return None
        if pos <= min(p for p, _ in entries):
            return None
        return sorted({value for _, value in entries if value is not None})


def _pos(node: Node) -> int:
    return int(node.get("Pos", {}).get("Offset", 0))


def _end(node: Node) -> int:
    return int(node.get("End", {}).get("Offset", 0))


def _line(node: Node) -> int:
    return int(node.get("Pos", {}).get("Line", 1))


def _unescape(raw: str, quoted: bool) -> str:
    """Remove the backslashes bash removes: all of them unquoted, only before
    `$`, backtick, `"`, `\\` and newline inside double quotes."""
    out: list[str] = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt == "\n":
                i += 2
                continue
            if not quoted or nxt in '$`"\\':
                out.append(nxt)
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


_ANSI_C = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"', "e": "\x1b"}


def _ansi_c(raw: str) -> str:
    return re.sub(r"\\(.)", lambda m: _ANSI_C.get(m.group(1), m.group(0)), raw)


def _literal_word(word: Node | None) -> str | None:
    """The word's value when it has no expansion at all, else None."""
    if word is None:
        return ""
    out: list[str] = []
    for part in word.get("Parts", []):
        kind = part.get("Type")
        if kind == "Lit":
            if not out and part["Value"].startswith("~"):
                return None  # tilde expansion
            out.append(_unescape(part["Value"], quoted=False))
        elif kind == "SglQuoted":
            value = part.get("Value", "")
            out.append(_ansi_c(value) if part.get("Dollar") else value)
        elif kind == "DblQuoted":
            inner = part.get("Parts", [])
            if any(p.get("Type") != "Lit" for p in inner):
                return None
            out.extend(_unescape(p["Value"], quoted=True) for p in inner)
        else:
            return None
    return "".join(out)


def _iter_nodes(node: object) -> Iterator[Node]:
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _iter_nodes(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_nodes(item)


def _collect_constants(tree: Node) -> _Constants:
    constants = _Constants()

    def mark(name: str, pos: int) -> None:
        constants.record(name, pos, None)

    def assign(node: Node) -> None:
        name = node.get("Name", {}).get("Value")
        if not name:
            return
        pos = _pos(node)
        if node.get("Append") or node.get("Index"):
            mark(name, pos)
        elif node.get("Array") is not None:
            elems: list[str] = []
            for elem in node["Array"].get("Elems") or []:
                value = None if elem.get("Index") else _literal_word(elem.get("Value"))
                if value is None:
                    mark(name, pos)
                    return
                elems.append(value)
            constants.record(name, pos, tuple(elems))
        else:
            value = _literal_word(node.get("Value"))
            constants.record(name, pos, None if value is None else (value,))

    in_function = {
        id(inner)
        for node in _iter_nodes(tree)
        if node.get("Type") == "FuncDecl"
        for inner in _iter_nodes(node.get("Body"))
    }

    for node in _iter_nodes(tree):
        kind = node.get("Type")
        if kind == "CallExpr":
            args = node.get("Args") or []
            if not args:
                for item in node.get("Assigns") or []:
                    assign(item)
            else:
                _mark_bound_names(args, mark)
        elif kind == "DeclClause":
            flags = "".join(
                (_literal_word(a.get("Value")) or "")
                for a in node.get("Args") or []
                if a.get("Naked") and a.get("Value") is not None
            )
            variant = node.get("Variant", {}).get("Value")
            # A function's local cannot tell what the name holds outside it.
            local = variant == "local" or (
                variant in ("declare", "typeset")
                and id(node) in in_function
                and "g" not in flags
            )
            for item in node.get("Args") or []:
                name = item.get("Name", {}).get("Value")
                if name and local:
                    mark(name, _pos(item))
                elif name and "n" in flags:
                    mark(name, _pos(item))  # nameref: an alias, not a value
                    target = _literal_word(item.get("Value"))
                    if target and _IDENTIFIER.fullmatch(target):
                        mark(target, _pos(item))
                elif name and not item.get("Naked"):
                    assign(item)
        elif kind == "ForClause":
            loop = node.get("Loop", {})
            if loop.get("Type") == "WordIter":
                mark(loop["Name"]["Value"], _pos(node))
        elif kind == "ParamExp":
            exp = node.get("Exp")
            if exp and exp.get("Op") in (":=", "="):
                mark(node["Param"]["Value"], _pos(node))
        elif kind in ("BinaryArithm", "UnaryArithm"):
            op = node.get("Op")
            if (kind == "BinaryArithm" and op in _ARITH_ASSIGN) or op in ("++", "--"):
                target = _literal_word(node.get("X"))
                if target and _IDENTIFIER.fullmatch(target):
                    mark(target, _pos(node))
    return constants


def _mark_bound_names(args: list[Node], mark: Callable[[str, int], None]) -> None:
    """Names a command binds without an assignment: `read X`, `printf -v X`."""
    command = _literal_word(args[0])
    words = [(_literal_word(a), _pos(a)) for a in args[1:]]
    if command in ("read", "mapfile", "readarray", "getopts", "unset", "let"):
        for word, pos in words:
            name = (word or "").split("=", 1)[0]
            if _IDENTIFIER.fullmatch(name):
                mark(name, pos)
    elif command == "printf":
        for (word, _), (target, pos) in itertools.pairwise(words):
            if word == "-v" and target and _IDENTIFIER.fullmatch(target):
                mark(target, pos)
    elif command == "eval":
        for arg in args[1:]:
            for node in _iter_nodes(arg):
                for key in ("Value",):
                    text = node.get(key)
                    if isinstance(text, str):
                        for match in _EVAL_ASSIGN.finditer(text):
                            mark(match.group(1), _pos(arg))


def _collect_functions(tree: Node) -> dict[str, list[Node]]:
    functions: dict[str, list[Node]] = {}
    for node in _iter_nodes(tree):
        if node.get("Type") == "FuncDecl":
            functions.setdefault(node["Name"]["Value"], []).append(node["Body"])
    return functions


def _uses_positional(body: Node) -> bool:
    """Whether the body reads its positional parameters (nested function
    definitions read their own)."""

    def visit(node: object) -> bool:
        if isinstance(node, list):
            return any(visit(item) for item in node)
        if not isinstance(node, dict) or node.get("Type") == "FuncDecl":
            return False
        if node.get("Type") == "ParamExp" and node["Param"]["Value"] in _POSITIONAL:
            return True
        return any(visit(value) for value in node.values())

    return visit(body)


def _has_root_word(body: Node) -> bool:
    return any(
        node.get("Type") == "Lit" and node.get("Value") in ("sudo", "doas")
        for node in _iter_nodes(body)
    )


# --- wrappers --------------------------------------------------------------


@dataclass(frozen=True)
class _Wrapper:
    short_value: str = ""
    long_value: frozenset[str] = frozenset()
    assignments: bool = False
    root: bool = False


_WRAPPERS: dict[str, _Wrapper] = {
    "sudo": _Wrapper(
        short_value="CDghpRrTtUu",
        long_value=frozenset(
            {
                "--close-from",
                "--chdir",
                "--group",
                "--host",
                "--prompt",
                "--chroot",
                "--role",
                "--type",
                "--command-timeout",
                "--other-user",
                "--user",
            }
        ),
        assignments=True,
        root=True,
    ),
    "doas": _Wrapper(short_value="Cu", root=True),
    "env": _Wrapper(
        short_value="uCS",
        long_value=frozenset({"--unset", "--chdir", "--split-string"}),
        assignments=True,
    ),
    "command": _Wrapper(),
    "exec": _Wrapper(short_value="a"),
    "nohup": _Wrapper(),
    "xargs": _Wrapper(
        short_value="EILPadens",
        long_value=frozenset(
            {
                "--arg-file",
                "--delimiter",
                "--eof",
                "--replace",
                "--max-lines",
                "--max-args",
                "--max-chars",
                "--max-procs",
                "--process-slot-var",
            }
        ),
    ),
}


def _unknown_word(text: str = "?") -> Arg:
    return Arg(text, None, expanded=True, splat=True)


def _wrapped(name: str, args: list[Arg]) -> list[list[Arg]]:
    """What a wrapper runs: one list per way of reading its arguments.

    An unknown multi-word argument may be the wrapper's flags or the command,
    so both readings are returned. An empty result means it runs nothing.
    """
    spec = _WRAPPERS[name]
    results: list[list[Arg]] = []
    i = 0
    while i < len(args):
        arg = args[i]
        text = arg.literal
        if arg.splat:
            results.append(args[i:])
            i += 1
            continue
        if text is None:
            break
        if text == "--":
            i += 1
            break
        if spec.assignments and _ASSIGN_WORD.match(text):
            i += 1
            continue
        if not (text.startswith("-") and len(text) > 1):
            break
        if name == "command" and any(ch in text[1:] for ch in "vV"):
            return []  # `command -v` looks a command up; it runs nothing
        if name == "env" and (text.startswith("-S") or text.startswith("--split")):
            return [[_unknown_word(text)]]
        i += 1
        if text.startswith("--"):
            if "=" not in text and text in spec.long_value:
                i += 1
            continue
        for k, letter in enumerate(text[1:]):
            if letter in spec.short_value:
                if k == len(text) - 2:
                    i += 1
                break
    results.append(args[i:])
    return [rest for rest in results if rest]


# --- builder ---------------------------------------------------------------


@dataclass
class _Frame:
    """An inlined function call: its positional parameters and locals."""

    positional: list[Arg] | None
    locals: dict[str, list[Arg]] = field(default_factory=dict)
    # Reads of the positional parameters or a local. A command that made none
    # is the same as its copy at the function definition.
    reads: int = 0
    call_line: int = 0


@dataclass(frozen=True)
class _Ctx:
    src: bytes
    line_offset: int = 0
    # Byte offset in the entry file used for constant lookups, for code that
    # is not at its own position there (embedded code, inlined bodies).
    lookup_pos: int | None = None
    function: str | None = None
    frame: _Frame | None = None
    pipeline: int | None = None
    stage: int = 0
    redirects: tuple[Redirect, ...] = ()
    as_root: bool = False
    depth: int = 0
    inlining: tuple[str, ...] = ()
    # The constants of each embedded program around this code, innermost
    # last; the entry file's own are the builder's.
    scopes: tuple[_Constants, ...] = ()

    def line(self, node: Node) -> int:
        return _line(node) + self.line_offset

    def at(self, node: Node) -> int:
        return self.lookup_pos if self.lookup_pos is not None else _pos(node)

    def slice(self, node: Node) -> str:
        return self.src[_pos(node) : _end(node)].decode("utf-8", errors="replace")


@dataclass(frozen=True)
class _Write:
    path: Arg
    heredoc: Redirect
    command: Command


class _Builder:
    def __init__(self, tree: Node, src: bytes, file: str, parse: Parser) -> None:
        self._src = src
        self._parse = parse
        self._constants = _collect_constants(tree)
        self._functions = _collect_functions(tree)
        self._inlinable = {
            name
            for name, bodies in self._functions.items()
            if any(_uses_positional(body) for body in bodies)
        }
        self._pipelines = itertools.count()
        self._writes: list[_Write] = []
        self.model = CommandModel(file=file)

    # statements

    def walk(self, stmts: Iterable[Node], ctx: _Ctx) -> None:
        for stmt in stmts:
            self._stmt(stmt, ctx)

    def _stmt(self, stmt: Node, ctx: _Ctx) -> None:
        reads_before = ctx.frame.reads if ctx.frame is not None else 0
        redirects = tuple(self._redirect(r, ctx) for r in stmt.get("Redirs") or [])
        cmd = stmt.get("Cmd")
        if cmd is None:
            return
        kind = cmd.get("Type")
        if kind == "CallExpr":
            self._call(cmd, stmt, ctx, (*ctx.redirects, *redirects), reads_before)
            return
        inner = replace(ctx, redirects=(*ctx.redirects, *redirects))
        if kind == "BinaryCmd":
            if cmd["Op"] in ("|", "|&"):
                self._pipeline(stmt, inner)
            else:
                self._stmt(cmd["X"], inner)
                self._stmt(cmd["Y"], inner)
        elif kind in ("Block", "Subshell"):
            self.walk(cmd.get("Stmts") or [], inner)
        elif kind == "IfClause":
            self._if(cmd, inner)
        elif kind == "WhileClause":
            self.walk(cmd.get("Cond") or [], inner)
            self.walk(cmd.get("Do") or [], inner)
        elif kind == "ForClause":
            self._substs(cmd.get("Loop"), inner)
            self.walk(cmd.get("Do") or [], inner)
        elif kind == "CaseClause":
            self._substs(cmd.get("Word"), inner)
            for item in cmd.get("Items") or []:
                self._substs(item.get("Patterns"), inner)
                self.walk(item.get("Stmts") or [], inner)
        elif kind == "FuncDecl":
            if ctx.inlining:
                return  # walked where it is defined; a call inlines it again
            body = replace(
                ctx,
                function=cmd["Name"]["Value"],
                frame=None,
                pipeline=None,
                redirects=(),
            )
            self._stmt(cmd["Body"], body)
        elif kind in ("TimeClause", "CoprocClause"):
            if cmd.get("Stmt"):
                self._stmt(cmd["Stmt"], inner)
        elif kind == "DeclClause":
            self._substs(cmd, inner)
            self._declare(cmd, inner)
        else:  # TestClause, ArithmCmd, LetClause, ...
            self._substs(cmd, inner)

    def _if(self, clause: Node, ctx: _Ctx) -> None:
        self.walk(clause.get("Cond") or [], ctx)
        self.walk(clause.get("Then") or [], ctx)
        if clause.get("Else"):
            self._if(clause["Else"], ctx)

    def _pipeline(self, stmt: Node, ctx: _Ctx) -> None:
        stages = _flatten_pipeline(stmt)
        pipeline = next(self._pipelines)
        first = len(self.model.commands)
        for i, stage in enumerate(stages):
            self._stmt(stage, replace(ctx, pipeline=pipeline, stage=i))
        self._piped_heredocs(self.model.commands[first:], pipeline, ctx)

    def _piped_heredocs(
        self, commands: list[Command], pipeline: int, ctx: _Ctx
    ) -> None:
        """`cat <<EOF | sh` runs the heredoc; `cat <<EOF | tee f` writes it."""
        for sender in commands:
            if sender.pipeline != pipeline or sender.name != "cat":
                continue
            for heredoc in sender.heredocs():
                for receiver in self.model.later_stages(sender):
                    if _reads_stdin_as_code(receiver):
                        self._embed(
                            heredoc.heredoc or "", heredoc.body_line, sender.pos, ctx
                        )
                    elif receiver.name == "tee":
                        self._record_writes(receiver, heredoc, _tee_files(receiver))

    # simple commands

    def _call(
        self,
        call: Node,
        stmt: Node,
        ctx: _Ctx,
        redirects: tuple[Redirect, ...],
        reads_before: int,
    ) -> None:
        self._substs(call, ctx)
        words = call.get("Args") or []
        if not words:
            for item in call.get("Assigns") or []:
                self._bind(item, ctx)
            return
        line = ctx.line(stmt)
        pos = ctx.at(stmt)
        self._positional_builtin(words, ctx)
        head_reads = ctx.frame.reads if ctx.frame is not None else 0
        self._word_alternatives(words[0], ctx)
        head_from_frame = ctx.frame is not None and ctx.frame.reads > head_reads
        alternatives = self._expand(words, ctx)
        if ctx.frame is not None and ctx.frame.reads == reads_before:
            return  # same as the command at the function's definition
        for argv in alternatives:
            for resolved, root in _strip_wrappers(argv):
                command_line = line
                if ctx.frame is not None:
                    # Inlined: report where the command word was written, so
                    # `execute_sudo "${CHMOD[@]}" ...` reports chmod at the
                    # call and a body's own `rm -rf "$1"` at the body line. A
                    # word rebuilt here from the caller's (`$CMD` from "$*")
                    # reports at the call.
                    head = resolved[0]
                    passed = any(head is a for a in ctx.frame.positional or ())
                    origin = head.line
                    if origin is None or (head_from_frame and not passed):
                        origin = ctx.frame.call_line
                    command_line = origin
                command = Command(
                    argv=resolved,
                    line=command_line,
                    file=self.model.file,
                    pos=pos,
                    index=len(self.model.commands),
                    as_root=root or ctx.as_root,
                    function=ctx.function,
                    redirects=redirects,
                    pipeline=ctx.pipeline,
                    stage=ctx.stage,
                )
                self.model.commands.append(command)
                self._follow(command, ctx)

    def _positional_builtin(self, words: list[Node], ctx: _Ctx) -> None:
        """Track `shift` and `set --` inside an inlined function body."""
        if ctx.frame is None or ctx.frame.positional is None:
            return
        name = _literal_word(words[0])
        if name == "shift":
            count = _literal_word(words[1]) if len(words) > 1 else "1"
            if count and count.isdigit():
                ctx.frame.positional = ctx.frame.positional[int(count) :]
            else:
                ctx.frame.positional = None
        elif name == "set" and len(words) > 1 and _literal_word(words[1]) == "--":
            ctx.frame.positional = None

    def _follow(self, command: Command, ctx: _Ctx) -> None:
        name = command.name
        if name in DOWNLOADERS:
            self._download(command)
        if name in SHELLS:
            self._shell(command, ctx)
        elif name in ("source", "."):
            files = parse_options(command.args).operands
            if not files or files[0].literal in ("/dev/stdin", "-"):
                for text, line in command.stdin_code():
                    self._embed(text, line, command.pos, ctx)
        elif name == "tee":
            for heredoc in command.heredocs():
                self._record_writes(command, heredoc, _tee_files(command))
        elif name == "cat":
            targets = [r.target for r in command.redirects if r.writes_stdout]
            for heredoc in command.heredocs():
                self._record_writes(command, heredoc, [t for t in targets if t])
        if name in self._inlinable:
            self._inline(command, name, ctx)

    def _shell(self, command: Command, ctx: _Ctx) -> None:
        code, files = _shell_code(command.args)
        if code is not None:
            text = code.literal if code.literal is not None else code.text
            self._embed(text, code.line or command.line, command.pos, ctx)
        elif not files:
            for text, line in command.stdin_code():
                self._embed(text, line or command.line, command.pos, ctx)

    def _inline(self, command: Command, name: str, ctx: _Ctx) -> None:
        if name in ctx.inlining or len(ctx.inlining) >= MAX_INLINE_DEPTH:
            return
        first = len(self.model.commands)
        for body in self._functions[name]:
            frame = _Frame(positional=list(command.args), call_line=command.line)
            inner = replace(
                ctx,
                src=self._src,  # function bodies are in the entry file
                line_offset=0,
                function=name,
                frame=frame,
                lookup_pos=command.pos,
                as_root=command.as_root,
                redirects=command.redirects,
                inlining=(*ctx.inlining, name),
                scopes=(),  # function bodies are in the entry file
            )
            self._stmt(body, inner)
        produced = self.model.commands[first:]
        args = command.args
        if (
            args
            and args[0].literal is not None
            and any(c.argv and c.argv[0].values is None for c in produced)
        ):
            # The body runs something it built from its arguments (k3d's
            # runAsRoot: `CMD="sudo $*"; $CMD`): treat it as a wrapper.
            root = command.as_root or any(
                _has_root_word(b) for b in self._functions[name]
            )
            wrapper = replace(
                ctx,
                function=name,
                frame=None,
                lookup_pos=command.pos,
                inlining=(*ctx.inlining, name),
            )
            for resolved, stripped_root in _strip_wrappers(list(args)):
                inner_command = replace(
                    command,
                    argv=resolved,
                    index=len(self.model.commands),
                    as_root=root or stripped_root,
                    function=name,
                )
                self.model.commands.append(inner_command)
                self._follow(inner_command, wrapper)

    # embedded code

    def _embed(self, text: str, line: int | None, pos: int, ctx: _Ctx) -> None:
        """Parse `text` as code run at `line`, and add its commands.

        `pos` is the embedding command's offset in the entry file, so the
        embedded code sees the constants assigned before that command.
        """
        first = line if line is not None else 1
        if not text.strip():
            return
        if ctx.depth >= MAX_EMBED_DEPTH:
            self.model.unparsed.append(Snippet(text, first, self.model.file))
            return
        try:
            tree = self._parse(text)
        except ShfmtError:
            self.model.unparsed.append(Snippet(text, first, self.model.file))
            return
        inner = replace(
            ctx,
            src=text.encode("utf-8"),
            line_offset=first - 1,
            lookup_pos=pos,
            pipeline=None,
            stage=0,
            redirects=(),
            depth=ctx.depth + 1,
            scopes=(*ctx.scopes, _collect_constants(tree)),
        )
        self.walk(tree.get("Stmts") or [], inner)

    # words

    def _substs(self, node: object, ctx: _Ctx) -> None:
        """Walk every `$(...)`, backtick and `<(...)` under `node`."""
        if isinstance(node, list):
            for item in node:
                self._substs(item, ctx)
            return
        if not isinstance(node, dict):
            return
        if node.get("Type") in ("CmdSubst", "ProcSubst"):
            inner = replace(ctx, pipeline=None, stage=0, redirects=())
            self.walk(node.get("Stmts") or [], inner)
            return
        for value in node.values():
            if isinstance(value, dict | list):
                self._substs(value, ctx)

    def _expand(self, words: list[Node], ctx: _Ctx) -> list[list[Arg]]:
        per_word = [self._word_alternatives(w, ctx) for w in words]
        total = 1
        for alternatives in per_word:
            total *= len(alternatives)
        if total > MAX_ALTERNATIVES:
            per_word = [
                alts if len(alts) == 1 else [[_unknown_word(self._text(w, ctx))]]
                for w, alts in zip(words, per_word, strict=True)
            ]
        results: list[list[Arg]] = []
        for combo in itertools.product(*per_word):
            argv = [arg for word in combo for arg in word]
            if not argv:
                continue
            head = argv[0]
            if head.values is not None and len(head.values) > 1:
                for value in sorted(head.values)[:MAX_ALTERNATIVES]:
                    results.append(
                        [replace(head, values=frozenset({value})), *argv[1:]]
                    )
            else:
                results.append(argv)
            if (head.splat or head.bare) and len(argv) > 1:
                # `$SUDO cmd ...` with SUDO unknown: it may be a wrapper or
                # empty, so also read the next word as the command.
                results.append(argv[1:])
        return results

    def _text(self, word: Node, ctx: _Ctx) -> str:
        return self._arg(word, ctx).text

    def _word_alternatives(self, word: Node, ctx: _Ctx) -> list[list[Arg]]:
        """One or more word lists a word can expand to (splitting, `"$@"`)."""
        parts = word.get("Parts") or []
        if len(parts) == 1:
            part = parts[0]
            line = ctx.line(word)
            if part.get("Type") == "ParamExp" and _plain(part):
                words = self._lookup(part, ctx)
                if words is None:
                    unknown = _unknown_word(_param_text(part))
                    if not _is_splat(part):
                        unknown = replace(unknown, splat=False, bare=True)
                    return [[replace(unknown, line=line)]]
                return [_split(alt, line) for alt in words]
            if part.get("Type") == "DblQuoted":
                inner = part.get("Parts") or []
                if len(inner) == 1 and _is_single_param(inner[0]):
                    words = self._lookup(inner[0], ctx)
                    if words is not None and all(len(alt) == 1 for alt in words):
                        if len(words) == 1:
                            return [[replace(words[0][0], line=line)]]
                if len(inner) == 1 and _is_splat(inner[0]):
                    words = self._lookup(inner[0], ctx)
                    if words is None:
                        return [
                            [replace(_unknown_word(_param_text(inner[0])), line=line)]
                        ]
                    return [
                        [
                            a if a.line is not None else replace(a, line=line)
                            for a in alt
                        ]
                        for alt in words
                    ]
        return [[self._arg(word, ctx)]]

    def _arg(self, word: Node, ctx: _Ctx) -> Arg:
        texts: list[str] = []
        value_sets: list[frozenset[str] | None] = []
        expanded = False
        for i, part in enumerate(word.get("Parts") or []):
            text, values, exp = self._part(part, ctx, quoted=False, first=i == 0)
            texts.append(text)
            value_sets.append(values)
            expanded = expanded or exp
        return Arg(
            "".join(texts),
            _concat(value_sets),
            expanded=expanded,
            line=ctx.line(word),
        )

    def _part(
        self, part: Node, ctx: _Ctx, quoted: bool, first: bool = False
    ) -> tuple[str, frozenset[str] | None, bool]:
        kind = part.get("Type")
        if kind == "Lit":
            raw = part.get("Value", "")
            text = _unescape(raw, quoted)
            if not quoted and first and raw.startswith("~"):
                return text, None, True  # tilde expansion
            return text, frozenset({text}), False
        if kind == "SglQuoted":
            value = part.get("Value", "")
            text = _ansi_c(value) if part.get("Dollar") else value
            return text, frozenset({text}), False
        if kind == "DblQuoted":
            texts: list[str] = []
            sets: list[frozenset[str] | None] = []
            expanded = False
            for inner in part.get("Parts") or []:
                text, values, exp = self._part(inner, ctx, quoted=True)
                texts.append(text)
                sets.append(values)
                expanded = expanded or exp
            return "".join(texts), _concat(sets), expanded
        if kind == "ParamExp":
            text = _param_text(part) if _plain(part) else ctx.slice(part)
            if _plain(part):
                words = self._lookup(part, ctx)
                if words is not None and len(words) == 1 and len(words[0]) == 1:
                    text = words[0][0].text  # the caller's text for "$1"
            return text, self._param_values(part, ctx), True
        return ctx.slice(part), None, True

    def _param_values(self, part: Node, ctx: _Ctx) -> frozenset[str] | None:
        if not _resolvable(part):
            return None
        words = self._lookup(part, ctx)
        if words is None:
            return None
        values: set[str] = set()
        for alt in words:
            sets = [a.values for a in alt]
            if any(s is None for s in sets):
                return None
            for combo in itertools.product(*[s for s in sets if s is not None]):
                values.add(" ".join(combo))
                if len(values) > MAX_VALUES:
                    return None
        exp = part.get("Exp")
        if exp and exp.get("Op") == ":-" and "" in values:
            default = self._arg(exp["Word"], ctx).values if exp.get("Word") else None
            if default is None:
                return None
            values = (values - {""}) | set(default)
        return frozenset(values)

    def _lookup(self, part: Node, ctx: _Ctx) -> list[list[Arg]] | None:
        """Alternative word lists for a parameter, honoring `[@]` and `[n]`."""
        name = part["Param"]["Value"]
        index = _index(part)
        frame = ctx.frame
        if frame is not None and (name in _POSITIONAL or name in frame.locals):
            frame.reads += 1
        if name in ("@", "*"):
            if frame is None or frame.positional is None:
                return None
            return [list(frame.positional)]
        if name.isdigit():
            if frame is None or frame.positional is None or name == "0":
                return None
            n = int(name)
            head = frame.positional[:n]
            if any(a.splat for a in head):
                return None
            if n > len(head):
                return [[Arg.lit("")]]
            return [[head[n - 1]]]
        if frame is not None and name in frame.locals:
            return _from_variable(_select(frame.locals[name], index))
        values = self._constant(name, part, ctx)
        if values is None:
            return None
        out: list[list[Arg]] = []
        for elements in values:
            chosen = _select([Arg.lit(e) for e in elements], index)
            if chosen is None:
                return None
            out.extend(chosen)
        return _from_variable(out)

    def _constant(
        self, name: str, part: Node, ctx: _Ctx
    ) -> list[tuple[str, ...]] | None:
        """A constant's values: the innermost embedded program that assigns
        the name answers (at this word, or for an enclosing program, at any
        point after its first assignment); else the entry file, at the
        position of the code that embeds this one. Outer values stay visible
        because the outer shell expands unquoted heredocs and "..." strings
        before the inner one runs."""
        for depth in range(len(ctx.scopes) - 1, -1, -1):
            scope = ctx.scopes[depth]
            if scope.assigns(name):
                innermost = depth == len(ctx.scopes) - 1
                return scope.lookup(name, _pos(part) if innermost else sys.maxsize)
        return self._constants.lookup(name, ctx.at(part))

    def _bind(self, assign: Node, ctx: _Ctx) -> None:
        """Record an assignment's value in an inlined body's locals."""
        frame = ctx.frame
        name = assign.get("Name", {}).get("Value")
        if frame is None or not name:
            return
        if assign.get("Append") or assign.get("Index"):
            frame.locals.pop(name, None)
        elif assign.get("Array") is not None:
            elems: list[Arg] = []
            for elem in assign["Array"].get("Elems") or []:
                if elem.get("Index") or elem.get("Value") is None:
                    frame.locals.pop(name, None)
                    return
                for alt in self._word_alternatives(elem["Value"], ctx)[:1]:
                    elems.extend(alt)
            frame.locals[name] = elems
        elif assign.get("Value") is None:
            frame.locals[name] = [Arg.lit("")]
        else:
            frame.locals[name] = [self._arg(assign["Value"], ctx)]

    def _declare(self, decl: Node, ctx: _Ctx) -> None:
        for item in decl.get("Args") or []:
            if item.get("Name") and not item.get("Naked"):
                self._bind(item, ctx)

    def _redirect(self, node: Node, ctx: _Ctx) -> Redirect:
        op = node["Op"]
        fd = node["N"]["Value"] if node.get("N") else None
        word = node.get("Word")
        if op in ("<<", "<<-"):
            quoted = _delimiter_quoted(word)
            hdoc = node.get("Hdoc")
            if hdoc is None:
                return Redirect(op, fd, None, "", None, quoted)
            if not quoted:
                self._substs(hdoc, ctx)  # expansions in the body run now
            parts = hdoc.get("Parts") or []
            if not parts:
                return Redirect(op, fd, None, "", ctx.line(hdoc), quoted)
            # Literal parts by value (their spans can run on to the delimiter),
            # expansions as their source text.
            body = "".join(
                p["Value"] if p.get("Type") == "Lit" else ctx.slice(p) for p in parts
            )
            if not quoted:
                body = re.sub(r"\\([$`\\])", r"\1", body)
            if op == "<<-":
                body = re.sub(r"(?m)^\t+", "", body)
            return Redirect(op, fd, None, body, ctx.line(hdoc), quoted)
        if word is not None:
            self._substs(word, ctx)
        return Redirect(op, fd, self._arg(word, ctx) if word else None)

    # downloads and generated files

    def _download(self, command: Command) -> None:
        if command.name == "curl":
            urls, out, remote = _curl_output(command.args)
        else:
            urls, out, remote = _wget_output(command.args)
        if any(a.splat for a in command.args) and out is None:
            path = None  # "$@" may hold -o; the path is unknown
        elif out is not None:
            path = None if out.literal == "-" else out
        elif remote and urls:
            path = _url_basename(urls[0])
        else:
            path = None
        if path is None:
            targets = [r.target for r in command.redirects if r.writes_stdout]
            path = targets[-1] if targets else None
        self.model.downloads.append(Download(command, tuple(urls), path))

    def _record_writes(
        self, command: Command, heredoc: Redirect, paths: Iterable[Arg]
    ) -> None:
        for path in paths:
            self._writes.append(_Write(path, heredoc, command))

    def finish(self) -> CommandModel:
        writes = [
            w
            for w in self._writes
            if path_names(w.path) and w.heredoc.body_line is not None
        ]
        chosen: set[int] = set()
        for command in self.model.commands:
            activated = [w for w in writes if _activates(command, w)]
            if activated:
                chosen.add(id(_nearest_write(command, activated)))
        seen: set[tuple[str, int | None]] = set()
        for write in writes:
            label = write.path.literal or write.path.text
            key = (label, write.heredoc.body_line)
            if id(write) not in chosen or key in seen:
                continue
            seen.add(key)
            self.model.generated.append(
                GeneratedFile(
                    path=write.path,
                    label=label,
                    text=write.heredoc.heredoc or "",
                    line=write.command.line,
                    body_line=write.heredoc.body_line or write.command.line,
                    file=self.model.file,
                )
            )
        return self.model


def _nearest_write(command: Command, writes: list[_Write]) -> _Write:
    """The write a run or chmod refers to: the last one before it, else the
    first one after it (a function defined earlier, called later)."""
    before = [w for w in writes if w.command.line <= command.line]
    if before:
        return max(before, key=lambda w: w.command.line)
    return min(writes, key=lambda w: w.command.line)


def _activates(command: Command, write: _Write) -> bool:
    """Whether `command` runs, installs or chmods +x the written file."""
    if command.index == write.command.index or not command.argv:
        return False
    if tied(command.argv[0], write.path):
        return True
    name = command.name
    if name == "chmod":
        mode, files = chmod_parts(command)
        return (
            mode is not None
            and adds_execute(mode)
            and any(tied(f, write.path) for f in files)
        )
    if name in SHELLS or name in ("source", "."):
        files = parse_options(command.args, short_value="oO").operands
        return bool(files) and tied(files[0], write.path)
    if name in ("install", "cp", "mv"):
        files = parse_options(command.args, short_value="mogtS").operands
        return any(tied(f, write.path) for f in files[:-1])
    return False


# --- helpers for the builder ------------------------------------------------


def _flatten_pipeline(stmt: Node) -> list[Node]:
    cmd = stmt.get("Cmd") or {}
    if cmd.get("Type") == "BinaryCmd" and cmd.get("Op") in ("|", "|&"):
        return [*_flatten_pipeline(cmd["X"]), *_flatten_pipeline(cmd["Y"])]
    return [stmt]


def _strip_wrappers(argv: list[Arg]) -> list[tuple[list[Arg], bool]]:
    """(argv, ran as root) for each command the wrappers may run."""
    done: list[tuple[list[Arg], bool]] = []
    todo: list[tuple[list[Arg], bool, int]] = [(argv, False, 0)]
    while todo:
        current, root, depth = todo.pop()
        head = current[0].literal if current else None
        name = posixpath.basename(head) if head else None
        if name not in _WRAPPERS or depth > MAX_INLINE_DEPTH:
            done.append((current, root))
            continue
        rests = _wrapped(name, current[1:])
        if not rests:
            done.append((current, root))  # a wrapper that runs nothing stays
            continue
        is_root = root or _WRAPPERS[name].root
        todo.extend((rest, is_root, depth + 1) for rest in rests)
    return list(reversed(done))


def _shell_code(args: list[Arg]) -> tuple[Arg | None, list[Arg]]:
    """(the `-c` string, script operands) of a sh/bash/zsh invocation."""
    i = 0
    wants_code = False
    reads_stdin = False
    while i < len(args):
        text = args[i].literal
        if args[i].splat or text is None:
            break
        if text in ("-", "--"):
            i += 1
            break
        if text.startswith("--"):
            i += 1
            continue
        if text[:1] in "-+" and len(text) > 1:
            letters = text[1:]
            wants_code = wants_code or "c" in letters
            reads_stdin = reads_stdin or "s" in letters
            i += 2 if text in ("-o", "+o", "-O", "+O") else 1
            continue
        break
    rest = args[i:]
    if wants_code:
        return (rest[0] if rest else None), []
    return None, ([] if reads_stdin else rest)


def _reads_stdin_as_code(command: Command) -> bool:
    if command.name in SHELLS:
        code, files = _shell_code(command.args)
        return code is None and not files
    if command.name in ("source", "."):
        files = parse_options(command.args).operands
        return bool(files) and files[0].literal in ("/dev/stdin", "-")
    return False


def _tee_files(command: Command) -> list[Arg]:
    return list(parse_options(command.args).operands)


def _delimiter_quoted(word: Node | None) -> bool:
    for part in (word or {}).get("Parts") or []:
        if part.get("Type") != "Lit" or any(c in part["Value"] for c in "\\'\""):
            return True
    return False


def _plain(part: Node) -> bool:
    """A bare `$X` / `${X}` / `${X[@]}`: no operator, length or slice."""
    return not any(
        part.get(key) for key in ("Exp", "Repl", "Slice", "Length", "Excl", "Width")
    )


def _resolvable(part: Node) -> bool:
    if any(part.get(key) for key in ("Repl", "Slice", "Length", "Excl", "Width")):
        return False
    exp = part.get("Exp")
    return exp is None or exp.get("Op") in (":?", "?", ":-")


def _is_single_param(part: Node) -> bool:
    return part.get("Type") == "ParamExp" and _plain(part) and not _is_splat(part)


def _is_splat(part: Node) -> bool:
    if part.get("Type") != "ParamExp" or not _plain(part):
        return False
    if part["Param"]["Value"] in ("@", "*"):
        return True
    return _index_literal(part) in ("@", "*")


def _index_literal(part: Node) -> str | None:
    index = part.get("Index")
    if index is None:
        return None
    return _literal_word(index) if index.get("Type") == "Word" else None


def _index(part: Node) -> str | None:
    """`@` for every element, a digit string for one, "0" for a bare name,
    None for an index that cannot be read."""
    if part.get("Index") is None:
        return "0"
    return _index_literal(part)


def _select(elements: list[Arg], index: str | None) -> list[list[Arg]] | None:
    if index in ("@", "*"):
        return [list(elements)]
    if index is None or not index.isdigit():
        return None
    n = int(index)
    if any(a.splat for a in elements[: n + 1]):
        return None
    return [[elements[n]]] if n < len(elements) else [[Arg.lit("")]]


def _param_text(part: Node) -> str:
    name = part["Param"]["Value"]
    index = _index_literal(part)
    return f"${{{name}[{index}]}}" if index is not None else f"${name}"


def _split(words: list[Arg], line: int) -> list[Arg]:
    """Word splitting of an unquoted expansion with known values."""
    out: list[Arg] = []
    for word in words:
        value = word.literal
        origin = word.line if word.line is not None else line
        if value is None:
            out.append(replace(word, bare=not word.splat, line=origin))
        else:
            out.extend(
                replace(Arg.lit(piece, line=origin), expanded=word.expanded)
                for piece in value.split()
            )
    return out


def _from_variable(
    alternatives: list[list[Arg]] | None,
) -> list[list[Arg]] | None:
    """A variable's value, still marked as an expansion: knowing what `$DIR`
    holds does not make `rm -rf "$DIR"` or `eval "$cmd"` literal code."""
    if alternatives is None:
        return None
    return [[replace(a, expanded=True) for a in alt] for alt in alternatives]


def _concat(sets: list[frozenset[str] | None]) -> frozenset[str] | None:
    if any(s is None for s in sets):
        return None
    values: set[str] = {""}
    for s in sets:
        values = {prefix + value for prefix in values for value in s or ()}
        if len(values) > MAX_VALUES:
            return None
    return frozenset(values)


_CURL_SHORT_VALUE = "ACDEFHKPQTUXYbcdemortuwxyz"
_CURL_LONG_VALUE = frozenset(
    {
        "--output",
        "--url",
        "--header",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "--user",
        "--user-agent",
        "--referer",
        "--write-out",
        "--request",
        "--upload-file",
        "--form",
        "--max-time",
        "--range",
        "--continue-at",
        "--config",
        "--cookie",
        "--cookie-jar",
        "--proxy",
        "--cert",
        "--cacert",
        "--capath",
        "--key",
        "--ciphers",
        "--proto",
        "--proto-redir",
        "--retry",
        "--retry-delay",
        "--retry-max-time",
        "--connect-timeout",
        "--max-redirs",
        "--limit-rate",
        "--resolve",
        "--interface",
        "--dns-servers",
        "--tls-max",
        "--output-dir",
        "--dump-header",
        "--proxy-user",
        "--time-cond",
        "--speed-limit",
        "--speed-time",
        "--expect100-timeout",
        "--happy-eyeballs-timeout-ms",
    }
)
_WGET_SHORT_VALUE = "ABDIOPQRTUXaeilotw"
_WGET_LONG_VALUE = frozenset(
    {
        "--output-document",
        "--output-file",
        "--append-output",
        "--directory-prefix",
        "--tries",
        "--timeout",
        "--wait",
        "--execute",
        "--input-file",
        "--user-agent",
        "--header",
        "--user",
        "--password",
        "--post-data",
        "--post-file",
        "--ca-certificate",
        "--certificate",
        "--private-key",
        "--load-cookies",
        "--save-cookies",
        "--quota",
        "--level",
        "--accept",
        "--reject",
        "--domains",
        "--base",
        "--secure-protocol",
        "--ciphers",
        "--limit-rate",
        "--referer",
        "--method",
        "--body-data",
        "--http-user",
        "--http-password",
        "--proxy-user",
        "--proxy-password",
        "--bind-address",
        "--progress",
    }
)


def _curl_output(args: list[Arg]) -> tuple[list[Arg], Arg | None, bool]:
    opts = parse_options(args, _CURL_SHORT_VALUE, _CURL_LONG_VALUE)
    urls = list(opts.operands)
    url = opts.value("--url")
    if url is not None:
        urls.append(url)
    remote = opts.has("-O", "--remote-name", "--remote-name-all")
    return urls, opts.value("-o", "--output"), remote


def _wget_output(args: list[Arg]) -> tuple[list[Arg], Arg | None, bool]:
    opts = parse_options(args, _WGET_SHORT_VALUE, _WGET_LONG_VALUE)
    urls = list(opts.operands)
    out = opts.value("-O", "--output-document")
    if out is not None:
        return urls, out, False
    prefix = opts.value("-P", "--directory-prefix")
    if prefix is not None and urls:
        name = _url_basename(urls[0])
        return urls, Arg(f"{prefix.text}/{name.text}", None, expanded=True), False
    return urls, None, True


def _url_basename(url: Arg) -> Arg:
    def base(value: str) -> str:
        return posixpath.basename(value.split("?", 1)[0].split("#", 1)[0])

    values = frozenset(base(v) for v in url.values) if url.values else None
    return Arg(base(url.text), values, expanded=url.expanded, line=url.line)


def build(tree: Node, text: str, file: str, parse: Parser) -> CommandModel:
    """The command model of the script `text`, whose shfmt tree is `tree`.

    `parse` turns embedded code into a tree (static/shfmt.parse in production)
    and raises ShfmtError when it cannot.
    """
    src = text.encode("utf-8")
    builder = _Builder(tree, src, file, parse)
    builder.walk(tree.get("Stmts") or [], _Ctx(src=src))
    return builder.finish()
