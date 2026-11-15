"""Rule ids, categories, footprint groups and messages, shared by the
syntax-tree rules and the regex fallback.

Rule ids are stable. Users and the model both see each message, so keep it to
one line of rationale. Every rule has a category (docs/spec.md, Finding
categories); every capability rule has a footprint group and a plain-words
label, the line the report shows under "What this script will do to your
machine".
"""

from __future__ import annotations

from typing import Literal

from chkscript.models import Category, Finding, Group, ScriptBundle, Severity

MESSAGES: dict[str, str] = {
    "curl-pipe-shell": (
        "Downloaded content is piped straight into a shell, so whatever the server "
        "returns runs unreviewed."
    ),
    "eval-remote": (
        "eval runs content fetched with curl or wget, so whatever the server "
        "returns runs unreviewed."
    ),
    "eval-dynamic": (
        "eval runs a string built from a variable or command output, which hides "
        "what actually executes."
    ),
    "decode-to-shell": (
        "Decoded or decompressed data is fed to a shell, a common way to hide a "
        "payload from review."
    ),
    "write-system-auth-file": (
        "The script writes to a system authentication or loader file, which can "
        "grant root or hijack every process."
    ),
    "persistence-append": (
        "The script installs something that runs again later: a shell rc file, "
        "crontab, systemd unit or init script."
    ),
    "insecure-permissions": (
        "World-writable files, or setuid/setgid or root-owned files in a "
        "user-writable location, let other users escalate privileges."
    ),
    "setuid-system": (
        "A file in a system path is made setuid or setgid, so it runs with its "
        "owner's privileges for every user."
    ),
    "rm-rf-unguarded": (
        "rm -rf on a variable followed by a path, or unquoted, deletes the wrong "
        "tree, or /, when the variable is empty or attacker-set."
    ),
    "rm-rf-variable": (
        "rm -rf on a quoted or guarded variable deletes whatever directory that "
        "variable names."
    ),
    "disable-security": (
        "The script turns off a host security control (SELinux, a firewall, or a "
        "security service)."
    ),
    "http-download": (
        "A download over plain http:// can be read or replaced by anyone on the "
        "network path."
    ),
    "unverified-download": (
        "An executable is downloaded with no sha256sum, shasum, gpg --verify or "
        "cosign check of that file; its integrity rests on TLS only."
    ),
    "runs-as-root": (
        "The script runs commands as root (sudo, doas, or a check that it is "
        "already root), so each of them can change anything on the machine."
    ),
    "system-path-write": (
        "The script writes into a system path (/usr/local, /opt, /usr/bin, "
        "/usr/lib or /etc), shared by every user of the machine."
    ),
    "package-repo-added": (
        "The script adds a package repository, so the machine installs that "
        "vendor's packages from now on."
    ),
    "root-equivalent-group": (
        "The script adds a user to a group whose members are root in practice "
        "(docker, lxd, libvirt or disk)."
    ),
}

# A message that depends on what the rule found, keyed by (rule id, variant).
VARIANT_MESSAGES: dict[tuple[str, str], str] = {
    ("package-repo-added", "scoped"): (
        "The script adds a package repository whose key is scoped to it "
        "(signed-by), so the machine installs that vendor's packages from now on."
    ),
    ("package-repo-added", "global"): (
        "The script adds a package repository or key trusted globally, which "
        "lets that vendor sign any package on the machine."
    ),
}

CATEGORIES: dict[str, Category] = {
    "curl-pipe-shell": "unsafe",
    "eval-remote": "unsafe",
    "eval-dynamic": "capability",
    "decode-to-shell": "unsafe",
    "write-system-auth-file": "unsafe",
    "persistence-append": "capability",
    "insecure-permissions": "unsafe",
    "setuid-system": "capability",
    "rm-rf-unguarded": "unsafe",
    "rm-rf-variable": "capability",
    "disable-security": "unsafe",
    "http-download": "unsafe",
    "unverified-download": "capability",
    "runs-as-root": "capability",
    "system-path-write": "capability",
    "package-repo-added": "capability",
    "root-equivalent-group": "capability",
}

# Every capability rule's footprint group (docs/spec.md, Footprint groups),
# including `hardcoded-secret`, which preprocessing produces (redact.py).
GROUPS: dict[str, Group] = {
    "runs-as-root": "root",
    "persistence-append": "persistence",
    "system-path-write": "system-write",
    "setuid-system": "system-write",
    "package-repo-added": "trust",
    "root-equivalent-group": "trust",
    "unverified-download": "download",
    "eval-dynamic": "other",
    "rm-rf-variable": "other",
    "hardcoded-secret": "other",
}

# The report's plain-words line for a capability finding, keyed by rule id or
# by "<rule id>:<variant>".
LABELS: dict[str, str] = {
    "runs-as-root": "Runs commands as root",
    "persistence-append": "Installs something that runs again later",
    "persistence-append:systemd": "Installs a systemd service",
    "persistence-append:service": "Installs a service",
    "persistence-append:cron": "Installs a cron job",
    "persistence-append:rc": "Changes shell startup files",
    "system-path-write": "Writes to system paths",
    "setuid-system": "Makes a system file setuid or setgid",
    "package-repo-added": "Adds a package repository",
    "package-repo-added:scoped": "Adds a package repository, key scoped to it",
    "package-repo-added:global": "Adds a package repository or key trusted globally",
    "root-equivalent-group": "Adds a user to a root-equivalent group",
    "unverified-download": "Downloads binaries verified only by TLS",
    "eval-dynamic": "Runs eval on a variable or command output",
    "rm-rf-variable": "Deletes a directory named by a variable",
    "hardcoded-secret": "Contains a hardcoded credential",
}

RULE_IDS: frozenset[str] = frozenset(MESSAGES)


def message(rule_id: str, variant: str | None = None) -> str:
    if variant is not None and (rule_id, variant) in VARIANT_MESSAGES:
        return VARIANT_MESSAGES[(rule_id, variant)]
    return MESSAGES[rule_id]


def label(rule_id: str, variant: str | None = None) -> str | None:
    """The report line for a capability rule; None for any other rule."""
    if variant is not None and f"{rule_id}:{variant}" in LABELS:
        return LABELS[f"{rule_id}:{variant}"]
    return LABELS.get(rule_id)


def finding(
    bundle: ScriptBundle,
    rule_id: str,
    line: int,
    source: Literal["shfmt", "regex"],
    variant: str | None = None,
    subject: str | None = None,
) -> Finding:
    """A rule's finding, the same under either engine: severity and category
    from CATEGORIES, and for a capability its group, label and subject."""
    category = CATEGORIES[rule_id]
    capability = category == "capability"
    return Finding(
        severity=Severity.UNSAFE if category == "unsafe" else Severity.WARNING,
        category=category,
        description=message(rule_id, variant),
        snippet=bundle.line_text(line),
        source=source,
        rule_id=rule_id,
        file=bundle.file,
        line=line,
        group=GROUPS[rule_id] if capability else None,
        label=label(rule_id, variant) if capability else None,
        subject=subject if capability else None,
    )


# Shared patterns: both engines match paths and services the same way.
SECURITY_SERVICES = (
    "apparmor|firewalld|ufw|auditd|fail2ban|iptables|nftables|clamav-daemon"
    "|clamd|falcon-sensor|osqueryd|wazuh-agent|selinux"
)
HOME = r"(?:~|\$HOME|\$\{HOME\})"
AUTH_FILE = r"/etc/(?:sudoers|passwd\b|shadow\b|ld\.so\.preload\b)"
RC_FILE = rf"{HOME}/\.(?:bashrc|bash_profile|profile|zshrc)\b"
SYSTEMD_PATH = (
    rf"(?:/etc/systemd/|/lib/systemd/|/usr/lib/systemd/|{HOME}/\.config/systemd/)"
)
# SysV and OpenRC service scripts: a service, like a systemd unit.
INIT_PATH = r"(?:/etc/init\.d/|/etc/rc\.d/)"
CRON_PATH = r"(?:/etc/cron|/var/spool/cron)"
SCHEDULER_PATH = rf"(?:{CRON_PATH}|{SYSTEMD_PATH}|{INIT_PATH})"
WORLD_WRITABLE_MODE = r"0?777"
SETID_MODE = r"(?:[ugoa]*\+[rwxt]*s[rwxt]*|0?[2467][0-7]{3})"
INSECURE_MODE = rf"(?:{WORLD_WRITABLE_MODE}|{SETID_MODE})"
USER_WRITABLE = rf"(?:{HOME}|/tmp)(?:/|$)"
# Where setuid/setgid is a capability rather than unsafe: root-owned system
# directories, which an unprivileged user cannot write.
SETID_SYSTEM_PATH = r"/(?:usr|opt|bin|sbin|lib|lib64|etc)/"
# system-path-write: the directories the issue names.
SYSTEM_PATH = r"/(?:usr/local|opt|usr/bin|usr/lib|etc)(?:/|$)"
APT_SOURCE = r"/etc/apt/sources\.list(?:\.d/|$)"
RPM_REPO = r"/etc/(?:yum\.repos\.d|zypp/repos\.d)/"
GLOBAL_APT_KEY = r"/etc/apt/trusted\.gpg(?:\.d/|$)"
# Repository and key files: package-repo-added's, so not system-path-write's.
REPO_PATH = (
    rf"(?:{APT_SOURCE}|{RPM_REPO}|{GLOBAL_APT_KEY}|/etc/apt/keyrings/"
    r"|/etc/pki/rpm-gpg/)"
)
ROOT_GROUPS = ("docker", "lxd", "libvirt", "disk")
