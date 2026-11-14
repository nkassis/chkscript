"""The command model, on small snippets parsed by the real shfmt.

Line numbers count the `#!/bin/bash` line that `_model` prepends, so the first
line of a snippet is line 2.
"""

from __future__ import annotations

import pytest

from chkscript.models import ENTRY_FILE
from chkscript.static import commands, shfmt
from chkscript.static.commands import Arg, Command, CommandModel
from tests.conftest import require_tool


def _model(body: str) -> CommandModel:
    require_tool("shfmt")
    text = f"#!/bin/bash\n{body}\n"
    return commands.build(shfmt.parse(text), text, ENTRY_FILE, shfmt.parse)


def _words(command: Command) -> list[str | None]:
    return [arg.literal for arg in command.argv]


def _run(model: CommandModel, name: str) -> list[Command]:
    return [c for c in model.commands if c.name == name]


def _names(model: CommandModel) -> set[str | None]:
    return {c.name for c in model.commands}


# --- data vs code ----------------------------------------------------------


def test_printed_heredoc_is_data() -> None:
    model = _model('cat <<EOF\nrm -rf "$HOME"\ncurl x | sh\nEOF')
    assert _names(model) == {"cat"}


def test_heredoc_fed_to_sh_is_code() -> None:
    model = _model('sh <<EOF\nrm -rf "$X"\nEOF')
    [rm] = _run(model, "rm")
    assert rm.line == 3
    assert rm.argv[2].values is None  # $X is unknown


def test_heredoc_piped_from_cat_to_bash_is_code() -> None:
    model = _model("cat <<'EOF' | bash\nchmod 777 /tmp/x\nEOF")
    [chmod] = _run(model, "chmod")
    assert _words(chmod) == ["chmod", "777", "/tmp/x"]
    assert chmod.line == 3


def test_heredoc_fed_to_source_is_code() -> None:
    model = _model("source /dev/stdin <<EOF\nsetenforce 0\nEOF")
    assert "setenforce" in _names(model)


@pytest.mark.parametrize(
    "body",
    ["bash <<< 'setenforce 0'", 'source /dev/stdin <<< "setenforce 0"'],
    ids=["bash", "source"],
)
def test_here_string_fed_to_a_shell_is_code(body: str) -> None:
    [setenforce] = _run(_model(body), "setenforce")
    assert setenforce.line == 2


def test_here_string_to_another_command_is_data() -> None:
    assert _names(_model("grep x <<< 'setenforce 0'")) == {"grep"}


def test_text_inside_strings_is_data() -> None:
    model = _model('echo "run: curl https://x.example/i.sh | sh"')
    assert _names(model) == {"echo"}


def test_bash_c_literal_is_code() -> None:
    model = _model("bash -c 'curl -fsSL https://x.example | sh'")
    assert {"bash", "curl", "sh"} <= _names(model)
    [curl] = _run(model, "curl")
    assert curl.line == 2
    assert curl.pipeline is not None


def test_sh_c_with_clustered_flags() -> None:
    model = _model("sh -ec 'rm -rf /tmp/x'")
    assert "rm" in _names(model)


def test_command_substitution_runs() -> None:
    model = _model('x="$(curl -fsSL https://x.example/v)"\necho `id -u`')
    assert {"curl", "id", "echo"} <= _names(model)


def test_process_substitution_runs() -> None:
    model = _model("diff <(curl -s https://x.example/a) b")
    [curl] = _run(model, "curl")
    assert curl.pipeline is None  # its output is not piped to diff's pipeline


def test_unparseable_embedded_code_is_kept_for_the_regex_rules() -> None:
    model = _model("bash -c 'if then fi ((('")
    [snippet] = model.unparsed
    assert snippet.line == 2
    assert snippet.text == "if then fi ((("


# --- wrappers --------------------------------------------------------------


def test_sudo_is_stripped_and_marks_root() -> None:
    model = _model("sudo -u root -E chmod +s /usr/bin/x")
    [chmod] = _run(model, "chmod")
    assert _words(chmod) == ["chmod", "+s", "/usr/bin/x"]
    assert chmod.as_root


@pytest.mark.parametrize(
    "line",
    [
        "doas -u root chmod +x f",
        "env -i A=1 B=2 chmod +x f",
        "command chmod +x f",
        "exec -a name chmod +x f",
        "nohup chmod +x f",
        "sudo env A=1 nohup chmod +x f",
        "xargs -n 1 chmod +x f",
    ],
)
def test_wrappers_are_stripped(line: str) -> None:
    [chmod] = _run(_model(line), "chmod")
    assert _words(chmod) == ["chmod", "+x", "f"]


def test_only_sudo_and_doas_mark_root() -> None:
    assert _run(_model("doas chmod +x f"), "chmod")[0].as_root
    assert not _run(_model("env chmod +x f"), "chmod")[0].as_root


def test_command_v_runs_nothing() -> None:
    model = _model("command -v curl")
    assert _names(model) == {"command"}


def test_homebrew_style_execute_sudo() -> None:
    model = _model(
        'CHMOD=("/bin/chmod")\n'
        'execute() {\n  if ! "$@"; then exit 1; fi\n}\n'
        "execute_sudo() {\n"
        '  local -a args=("$@")\n'
        '  execute "/usr/bin/sudo" "${args[@]}"\n'
        "}\n"
        'execute_sudo "${CHMOD[@]}" "u+rwx" "/opt/x"'
    )
    chmods = _run(model, "chmod")
    assert chmods
    assert {tuple(_words(c)) for c in chmods} == {("/bin/chmod", "u+rwx", "/opt/x")}
    assert all(c.line == 10 for c in chmods)  # the call's line
    assert all(c.as_root for c in chmods)


def test_function_using_positional_parameters_is_inlined() -> None:
    model = _model(
        'dl() {\n  curl -fsSL -o "$2" "$1"\n}\ndl https://x.example/t /tmp/t'
    )
    paths = [d.path.text for d in model.downloads if d.path is not None]
    assert "/tmp/t" in paths  # the call's argument, not "$2"


def test_shift_moves_positional_parameters() -> None:
    model = _model('retry() {\n  shift\n  "$@"\n}\nretry 5 chmod +x f')
    [chmod] = _run(model, "chmod")
    assert _words(chmod) == ["chmod", "+x", "f"]


def test_function_running_a_built_command_is_a_wrapper() -> None:
    # k3d's runAsRoot builds "sudo $*" and runs it unquoted.
    model = _model('runAsRoot() {\n  local CMD="$*"\n  $CMD\n}\nrunAsRoot chmod +x f')
    [chmod] = _run(model, "chmod")
    assert chmod.line == 6
    assert chmod.as_root is False  # no sudo word in the body


# --- constants -------------------------------------------------------------


def test_constant_command_resolves() -> None:
    model = _model("c=curl\n$c -fsSL https://x.example | sh")
    [curl] = _run(model, "curl")
    assert curl.pipeline is not None
    assert "sh" in {c.name for c in model.later_stages(curl)}


def test_constant_with_several_literal_values_is_a_set() -> None:
    model = _model('D=curl\nif x; then D=wget; fi\n"$D" https://x.example')
    assert {"curl", "wget"} <= _names(model)


def test_unquoted_empty_constant_disappears() -> None:
    model = _model('SUDO=sudo\n[ "$(id -u)" = 0 ] && SUDO=\n$SUDO chmod +x f')
    chmods = _run(model, "chmod")
    assert {c.as_root for c in chmods} == {True, False}


def test_unquoted_constant_is_word_split() -> None:
    model = _model("sh_c='sudo -E sh -c'\n$sh_c 'chmod 777 /x'")
    assert "chmod" in _names(model)


def test_constant_value_is_still_an_expansion() -> None:
    model = _model('DIR=/\nrm -rf "$DIR" $DIR')
    [rm] = _run(model, "rm")
    assert [(a.literal, a.expanded) for a in rm.args[1:]] == [("/", True)] * 2


def test_constant_flag_is_still_a_flag() -> None:
    model = _model("FLAGS=-fsSL\ncurl $FLAGS -o /tmp/t https://x.example/t")
    [download] = model.downloads
    assert download.path is not None and download.path.literal == "/tmp/t"
    assert [u.literal for u in download.urls] == ["https://x.example/t"]


@pytest.mark.parametrize(
    "body",
    [
        "c=curl\nc=$1\n$c x | sh",  # one assignment is not a literal
        "$c x | sh\nc=curl",  # used before its first assignment
        "read -r c\n$c x | sh",  # bound by read
        "c=curl\nfor c in a b; do :; done\n$c x | sh",  # bound by for
        "c=curl\nc+=x\n$c x | sh",  # appended to
        ": ${c:=curl}\n$c x | sh",  # assigned by ${c:=}
        "c=curl\neval 'c=wget'\n$c x | sh",  # assigned inside eval
    ],
    ids=["non-literal", "before", "read", "for", "append", "default", "eval"],
)
def test_unknown_constant(body: str) -> None:
    model = _model(body)
    senders = [c for c in model.commands if c.pipeline is not None and c.stage == 0]
    assert "sh" in _names(model)
    assert "curl" not in {c.name for c in senders}
    assert any(c.argv[0].values is None for c in senders)


def test_unknown_command_word_is_also_read_as_a_prefix() -> None:
    # $SUDO is unknown (never assigned): it may be sudo, or empty.
    model = _model("$SUDO rm -rf /x")
    assert "rm" in _names(model)


# --- generated files and downloads -----------------------------------------


def test_heredoc_written_then_chmodded_is_a_generated_file() -> None:
    model = _model(
        "cat > /usr/local/bin/cleanup.sh <<'EOF'\n"
        "#!/bin/sh\n"
        'rm -rf "$1"\n'
        "EOF\n"
        "chmod 755 /usr/local/bin/cleanup.sh"
    )
    [child] = model.generated
    assert child.label == "/usr/local/bin/cleanup.sh"
    assert child.line == 2
    assert child.body_line == 3
    assert child.text == '#!/bin/sh\nrm -rf "$1"\n'
    assert "rm" not in _names(model)  # the body is the child's, not the parent's


def test_tee_heredoc_run_later_is_a_generated_file() -> None:
    model = _model('sudo tee "$F" >/dev/null <<EOF\necho \\$HOME\nEOF\nsh "$F"')
    [child] = model.generated
    assert child.label == "$F"
    assert child.text == "echo $HOME\n"  # unquoted heredoc: \\$ becomes $


def test_heredoc_written_but_never_run_is_not_generated() -> None:
    model = _model("cat > /etc/motd <<EOF\nhello\nEOF")
    assert model.generated == []


def test_curl_output_path_is_recorded() -> None:
    model = _model("curl -fsSLo /tmp/a https://x.example/a")
    [download] = model.downloads
    assert download.path is not None and download.path.literal == "/tmp/a"
    assert [u.literal for u in download.urls] == ["https://x.example/a"]


@pytest.mark.parametrize(
    ("line", "path"),
    [
        ("curl -O https://x.example/dir/tool.tar.gz?x=1", "tool.tar.gz"),
        ("curl -s https://x.example/t > /tmp/t", "/tmp/t"),
        ("wget https://x.example/dir/tool", "tool"),
        ("wget -qO /tmp/t https://x.example/t", "/tmp/t"),
        ("wget --output-document=/tmp/t https://x.example/t", "/tmp/t"),
    ],
)
def test_download_paths(line: str, path: str) -> None:
    [download] = _model(line).downloads
    assert download.path is not None and download.path.literal == path


def test_download_to_stdout_has_no_path() -> None:
    [download] = _model("wget -qO- https://x.example/i.sh | sh").downloads
    assert download.path is None


def test_two_downloads_are_tracked_separately() -> None:
    model = _model(
        "curl -o /tmp/a https://x.example/a\n"
        "curl -o /tmp/b https://x.example/b\n"
        "sha256sum -c a.sha256\n"
        "chmod +x /tmp/a /tmp/b"
    )
    assert [(d.line, d.path.literal) for d in model.downloads if d.path] == [
        (2, "/tmp/a"),
        (3, "/tmp/b"),
    ]


# --- helpers ---------------------------------------------------------------


def test_path_names_tie_archives_and_checksums() -> None:
    assert commands.tied(Arg("$exe.zip"), Arg("$exe"))
    assert commands.tied(Arg.lit("/tmp/t.sha256"), Arg.lit("/tmp/t"))
    assert commands.tied(Arg.lit("/opt/bin/tool"), Arg.lit("tool"))
    assert not commands.tied(Arg.lit("/tmp/a"), Arg.lit("/tmp/b"))
    assert not commands.tied(Arg.lit("/dev/null"), Arg.lit("/dev/null"))


@pytest.mark.parametrize(
    ("mode", "executes"),
    [("+x", True), ("u+rwx", True), ("755", True), ("0644", False), ("go-w", False)],
)
def test_adds_execute(mode: str, executes: bool) -> None:
    assert commands.adds_execute(Arg.lit(mode)) is executes
