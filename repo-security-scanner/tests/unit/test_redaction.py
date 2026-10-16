from __future__ import annotations

import logging

import pytest

from reposcan.redaction import (
    REDACTED,
    RedactingFilter,
    redact_text,
    redact_value,
    sanitize,
    sanitize_evidence,
    strip_control,
)

# Synthetic, structurally plausible values assembled at runtime so no scanner flags this file.
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
SLACK = "xoxb-" + "123456789012-abcdefghijkl"
JWT = (
    "eyJ"
    + "hbGciOiJIUzI1NiJ9"
    + ".eyJ"
    + "zdWIiOiIxMjM0NTY3ODkwIn0"
    + ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)
DEMO = "DEMO_TOKEN_" + "A" * 24


@pytest.mark.parametrize(
    "secret",
    [AWS, GH, SLACK, JWT, DEMO, "sk_live_" + "x" * 24, "AIza" + "S" * 35, "glpat-" + "x" * 20],
    # Readable ids: parameter ids must never embed credential-shaped strings (they reach logs/caches).
    ids=["aws", "github", "slack", "jwt", "demo-token", "stripe", "google", "gitlab"],
)
def test_known_credential_shapes_are_redacted(secret: str) -> None:
    out = redact_text(f"value is {secret} here")
    assert secret not in out
    assert "REDACTED" in out


def test_redaction_keeps_prefix_and_length_for_triage() -> None:
    masked = redact_value("AKIA" + "ABCDEFGHIJKLMNOP")
    assert masked.startswith("AK")
    assert ":20]" in masked
    assert len(masked) < 20


def test_short_values_are_fully_masked() -> None:
    assert redact_value("hunter2") == REDACTED


@pytest.mark.parametrize(
    "line",
    [
        'password = "correct-horse-battery"',
        "export API_KEY=0123456789abcdef0123",
        '{"client_secret": "s3cr3t-value-123"}',
        "db: postgres://admin:Sup3rS3cret@db.internal/app",
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789",
    ],
)
def test_assignments_and_urls_are_redacted(line: str) -> None:
    out = redact_text(line)
    for leaked in (
        "correct-horse-battery",
        "0123456789abcdef0123",
        "s3cr3t-value-123",
        "Sup3rS3cret",
        "abcdefghijklmnopqrstuvwxyz0123456789",
    ):
        assert leaked not in out


def test_private_key_block_is_removed() -> None:
    # Assembled at runtime from a plainly fake body so no secret scanner flags this file.
    header, footer = "-----BEGIN RSA " + "PRIVATE KEY-----", "-----END RSA " + "PRIVATE KEY-----"
    body = "c3ludGhldGljLXRlc3Qta2V5LWJvZHktbm90LWEtcmVhbC1rZXk" * 2
    block = f"{header}\n{body}\n{footer}"
    assert body not in redact_text(block)


def test_extra_secrets_are_replaced_exactly() -> None:
    assert "plainsecretvalue" not in redact_text("x plainsecretvalue y", ["plainsecretvalue"])


def test_already_redacted_values_are_stable() -> None:
    once = redact_text('token = "abcdefghijklmnopqrstuvwxyz123456"')
    assert redact_text(once) == once


def test_control_and_escape_sequences_are_stripped() -> None:
    hostile = "ok\x1b[31mred\x1b]0;title\x07\x00‮txt\r\n"
    cleaned = strip_control(hostile)
    assert "\x1b" not in cleaned and "\x00" not in cleaned and "‮" not in cleaned
    assert cleaned.startswith("okred")


def test_sanitize_truncates() -> None:
    assert len(sanitize("a" * 1000, limit=50)) == 50


def test_evidence_is_collapsed_and_bounded() -> None:
    out = sanitize_evidence("  x   =  1 \n\n" + "y" * 1000)
    assert "\n" not in out and len(out) <= 240


def test_logging_filter_redacts_messages_args_and_exceptions(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("reposcan.test-redaction")
    handler = logging.Handler()
    records: list[logging.LogRecord] = []
    handler.emit = records.append  # type: ignore[method-assign]
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        try:
            raise RuntimeError(f"failed with {GH}")
        except RuntimeError:
            logger.error("token %s leaked", AWS, exc_info=True)
    finally:
        logger.removeHandler(handler)
    text = records[0].getMessage()
    assert AWS not in text and GH not in text
    assert records[0].exc_info is None
