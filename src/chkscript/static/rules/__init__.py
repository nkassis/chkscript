"""Unsafe-tier rules: Python functions over the command model.

Each rule takes a CommandModel (static/commands.py) and yields a Hit per
offending line. Rules never read script text, so a heredoc printed to the user
or a quoted string can never fire one. Ids and messages live in catalog.py,
shared with the regex fallback (static/regex_rules.py).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from chkscript.static.commands import CommandModel
from chkscript.static.rules import downloads, execution, pipelines, writes
from chkscript.static.rules.catalog import MESSAGES, RULE_IDS
from chkscript.static.rules.common import Hit

Rule = Callable[[CommandModel], Iterable[Hit]]

RULES: tuple[Rule, ...] = (
    pipelines.curl_pipe_shell,
    pipelines.decode_to_shell,
    execution.eval_dynamic,
    execution.rm_rf_variable,
    execution.disable_security,
    execution.http_download,
    writes.write_system_auth_file,
    writes.persistence_append,
    writes.insecure_permissions,
    downloads.unverified_download,
)

__all__ = ["MESSAGES", "RULES", "RULE_IDS", "Hit", "run"]


def run(model: CommandModel) -> list[Hit]:
    """Every rule's hits, deduplicated, in line order."""
    hits = {hit for rule in RULES for hit in rule(model)}
    return sorted(hits, key=lambda h: (h.line, h.rule_id))
