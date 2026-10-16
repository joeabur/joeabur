"""Detached Ed25519 baseline signatures (requires the optional ``cryptography`` package).

Signature file format (UTF-8 text, ``<baseline>.sig``)::

    fim-signature-v1
    algorithm: ed25519
    key-id: sha256:<hex of raw 32-byte public key>
    signature: <base64>

The signed message is ``b"fim-baseline-signature-v1\\n" + <exact baseline file bytes>``; the
domain-separation prefix stops a baseline signature being replayed as anything else.

Private keys are never stored by FIM: ``keygen`` writes them to a path you choose (mode 0600,
refusing to overwrite) and the CLI refuses locations inside the baseline directory or any
monitored root.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import stat
from typing import TYPE_CHECKING, Any

from fim.errors import DependencyError, TrustError

if TYPE_CHECKING:  # pragma: no cover
    pass

SIG_MAGIC = "fim-signature-v1"
_PREFIX = b"fim-baseline-signature-v1\n"


def _crypto() -> Any:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch in tests
        raise DependencyError(
            "signing needs the 'cryptography' package: pip install 'fim-tool[signing]'"
        ) from exc
    return serialization, ed25519


def key_id(public_raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(public_raw).hexdigest()


def _raw_public(pub: Any, serialization: Any) -> bytes:
    raw: bytes = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw


def generate_keypair(private_path: str, public_path: str, passphrase: bytes | None = None) -> str:
    """Create a new keypair; refuses to overwrite either file. Returns the key id."""
    serialization, ed25519 = _crypto()
    key = ed25519.Ed25519PrivateKey.generate()
    enc = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    priv_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    pub = key.public_key()
    pub_pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    _create_exclusive(private_path, priv_pem, 0o600)
    try:
        _create_exclusive(public_path, pub_pem, 0o644)
    except FileExistsError:
        os.unlink(private_path)  # do not leave an orphan private key behind
        raise
    return key_id(_raw_public(pub, serialization))


def _create_exclusive(path: str, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, mode)


def _load_private(path: str, passphrase: bytes | None) -> Any:
    serialization, ed25519 = _crypto()
    st = os.stat(path)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise TrustError(f"private key {path} is accessible by group/others; chmod 600 it")
    with open(path, "rb") as fh:
        pem = fh.read()
    try:
        key = serialization.load_pem_private_key(pem, password=passphrase)
    except (ValueError, TypeError) as exc:
        raise TrustError(f"cannot load private key {path}: {exc}") from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TrustError("private key is not an Ed25519 key")
    return key


def load_public(path: str) -> tuple[Any, str]:
    serialization, ed25519 = _crypto()
    try:
        with open(path, "rb") as fh:
            pem = fh.read(64 * 1024)
        pub = serialization.load_pem_public_key(pem)
    except (OSError, ValueError) as exc:
        raise TrustError(f"cannot load public key {path}: {exc}") from exc
    if not isinstance(pub, ed25519.Ed25519PublicKey):
        raise TrustError("public key is not an Ed25519 key")
    return pub, key_id(_raw_public(pub, serialization))


def sign_bytes(private_path: str, data: bytes, passphrase: bytes | None = None) -> tuple[str, str]:
    """Return ``(signature file text, key id)``."""
    serialization, _ = _crypto()
    key = _load_private(private_path, passphrase)
    kid = key_id(_raw_public(key.public_key(), serialization))
    sig = base64.b64encode(key.sign(_PREFIX + data)).decode("ascii")
    text = f"{SIG_MAGIC}\nalgorithm: ed25519\nkey-id: {kid}\nsignature: {sig}\n"
    return text, kid


def parse_signature(text: str) -> tuple[str, bytes]:
    lines = text.splitlines()
    if len(lines) != 4 or lines[0] != SIG_MAGIC:
        raise TrustError("signature file is malformed")
    fields = {}
    for line in lines[1:]:
        k, sep, v = line.partition(": ")
        if not sep:
            raise TrustError("signature file is malformed")
        fields[k] = v
    if fields.get("algorithm") != "ed25519" or set(fields) != {"algorithm", "key-id", "signature"}:
        raise TrustError("unsupported or malformed signature file")
    try:
        raw = base64.b64decode(fields["signature"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TrustError("signature is not valid base64") from exc
    return fields["key-id"], raw


def verify_signature(public_key_path: str, data: bytes, sig_text: str) -> str:
    """Verify ``data`` against ``sig_text`` using the trusted public key. Returns the key id."""
    pub, kid = load_public(public_key_path)
    sig_kid, sig = parse_signature(sig_text)
    if sig_kid != kid:
        raise TrustError(f"signature was made by {sig_kid}, trusted key is {kid}")
    try:
        pub.verify(sig, _PREFIX + data)
    except Exception as exc:  # cryptography.exceptions.InvalidSignature
        raise TrustError("baseline signature does not match the baseline contents") from exc
    return kid
