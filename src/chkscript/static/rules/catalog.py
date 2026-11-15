"""Rule ids and messages, shared by the syntax-tree rules and the regex fallback.

Rule ids are stable. Users and the model both see each message, so keep it to
one line of rationale.
"""

from __future__ import annotations

MESSAGES: dict[str, str] = {
    "curl-pipe-shell": (
        "Downloaded content is piped straight into a shell, so whatever the server "
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
        "The script installs itself to run again later via a shell rc file, "
        "crontab or systemd unit."
    ),
    "insecure-permissions": (
        "World-writable, setuid/setgid, or root-owned files in a user-writable "
        "location let other users escalate privileges."
    ),
    "rm-rf-variable": (
        "rm -rf on a path containing a variable deletes the wrong tree, or /, when "
        "the variable is empty or attacker-set."
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
        "cosign check of that file."
    ),
}

RULE_IDS: frozenset[str] = frozenset(MESSAGES)

# Shared patterns: both engines match paths and services the same way.
SECURITY_SERVICES = (
    "apparmor|firewalld|ufw|auditd|fail2ban|iptables|nftables|clamav-daemon"
    "|clamd|falcon-sensor|osqueryd|wazuh-agent|selinux"
)
HOME = r"(?:~|\$HOME|\$\{HOME\})"
AUTH_FILE = r"/etc/(?:sudoers|passwd\b|shadow\b|ld\.so\.preload\b)"
RC_FILE = rf"{HOME}/\.(?:bashrc|bash_profile|profile|zshrc)\b"
SCHEDULER_PATH = (
    rf"(?:/etc/cron|/var/spool/cron|/etc/systemd/|/lib/systemd/"
    rf"|/usr/lib/systemd/|{HOME}/\.config/systemd/)"
)
INSECURE_MODE = r"(?:0?777|[ugoa]*\+[rwxt]*s[rwxt]*|0?[2467][0-7]{3})"
USER_WRITABLE = rf"(?:{HOME}|/tmp)(?:/|$)"
