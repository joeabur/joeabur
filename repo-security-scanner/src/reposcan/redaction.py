"""Secret redaction and sanitisation of untrusted text.

Everything that reaches a log line, console message or report passes through
:func:`sanitize` (or :func:`redact_text`). Redaction is best effort and works
by shape, so scanners are additionally asked to redact at the source (for
example ``gitleaks --redact``).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable

REDACTED = "[REDACTED]"
MAX_EVIDENCE_CHARS = 240

# ESC sequences (CSI/OSC) and C0/C1 control characters other than \t and \n.
_ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]")

# (name, pattern, group index holding the secret value)
_PATTERNS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    (
        "private-key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
        0,
    ),
    ("aws-access-key", re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16})\b"), 1),
    (
        "github-token",
        re.compile(r"\b((?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_\w{20,255}))\b"),
        1,
    ),
    ("gitlab-token", re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"), 1),
    ("slack-token", re.compile(r"\b(xox[abprs]-[A-Za-z0-9\-]{10,})\b"), 1),
    ("stripe-key", re.compile(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b"), 1),
    ("google-api-key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 1),
    (
        "jwt",
        re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"),
        1,
    ),
    ("demo-token", re.compile(r"\b(DEMO_TOKEN_[A-Za-z0-9]{8,})\b"), 1),
    ("bearer", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/\-]{16,}=*)"), 1),
    ("url-credentials", re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s/:@]+:([^\s/@]+)@"), 1),
    (
        "assignment",
        re.compile(
            r"""(?ix)
            (?:pass(?:word|wd)?|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key
               |private[_\-]?key|client[_\-]?secret|credential|auth)\w*
            ["']?\s*[:=]\s*
            (?:["'`]([^"'`\s]{4,})["'`]|([^\s"'`,;]{4,}))
            """
        ),
        -1,  # either group 1 or 2
    ),
)


def strip_control(text: str) -> str:
    """Remove terminal escape sequences and control characters."""
    return _CONTROL_RE.sub("", _ANSI_RE.sub("", text))


def redact_value(value: str) -> str:
    """Mask a secret, keeping a short prefix and the length for triage."""
    if len(value) <= 8:
        return REDACTED
    keep = min(4, len(value) // 8)
    return f"{value[:keep]}{REDACTED[:-1]}:{len(value)}]"


def redact_text(text: str, extra_secrets: Iterable[str] = ()) -> str:
    """Redact credential-shaped substrings (and any explicitly known secrets)."""
    for secret in extra_secrets:
        if secret and len(secret) >= 4:
            text = text.replace(secret, redact_value(secret))
    for _name, pattern, group in _PATTERNS:
        text = pattern.sub(_replacer(group), text)
    return text


def _replacer(group: int) -> Callable[[re.Match[str]], str]:
    def replace(match: re.Match[str]) -> str:
        return _replace(match, group)

    return replace


def _replace(match: re.Match[str], group: int) -> str:
    if group == 0:
        return REDACTED
    if group == -1:
        group = 1 if match.group(1) is not None else 2
    value = match.group(group)
    if value is None or REDACTED[:-1] in value or value == "REDACTED":
        return match.group(0)
    start, end = match.span(group)
    full = match.group(0)
    offset = match.start()
    return full[: start - offset] + redact_value(value) + full[end - offset :]


def sanitize(text: str, *, limit: int | None = None, extra_secrets: Iterable[str] = ()) -> str:
    """Strip control characters, redact secrets and optionally truncate."""
    cleaned = redact_text(strip_control(text), extra_secrets)
    if limit is not None and len(cleaned) > limit:
        cleaned = cleaned[: max(limit - 1, 0)] + "…"
    return cleaned


def sanitize_evidence(text: str, extra_secrets: Iterable[str] = ()) -> str:
    """Normalise whitespace, redact and bound a code snippet used as evidence."""
    collapsed = " ".join(text.strip().split())
    return sanitize(collapsed, limit=MAX_EVIDENCE_CHARS, extra_secrets=extra_secrets)


class RedactingFilter(logging.Filter):
    """Logging filter guaranteeing that log records are redacted and control-free."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - malformed log call
            message = str(record.msg)
        record.msg = sanitize(message)
        record.args = None
        if record.exc_info:
            # Exceptions can embed untrusted text; keep only the type and sanitised text.
            exc_type, exc, _tb = record.exc_info
            record.msg = f"{record.msg} ({getattr(exc_type, '__name__', 'error')}: {sanitize(str(exc))})"
            record.exc_info = None
            record.exc_text = None
        return True


def install_log_redaction(handler: logging.Handler) -> None:
    handler.addFilter(RedactingFilter())
