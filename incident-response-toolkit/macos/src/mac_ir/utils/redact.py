"""Configurable redaction of secrets in command lines, logs and reports."""

from __future__ import annotations

import re
from typing import Any


class Redactor:
    def __init__(self, patterns: list[dict[str, str]], enabled: bool = True) -> None:
        self.enabled = enabled
        self._compiled: list[tuple[re.Pattern[str], str]] = []
        for p in patterns:
            self._compiled.append((re.compile(p["pattern"]), p.get("replacement", "[REDACTED]")))

    def text(self, value: str) -> str:
        if not self.enabled or not value:
            return value
        for rx, repl in self._compiled:
            value = rx.sub(repl, value)
        return value

    def data(self, obj: Any) -> Any:
        """Recursively redact strings inside JSON-like structures."""
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, list):
            return [self.data(i) for i in obj]
        if isinstance(obj, dict):
            return {k: self.data(v) for k, v in obj.items()}
        return obj
