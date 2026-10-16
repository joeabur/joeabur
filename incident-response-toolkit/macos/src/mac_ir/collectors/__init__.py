"""Collector registry. Each collector exposes NAME, DESCRIPTION, PRIVILEGE_NOTE, plan(), collect()."""

from __future__ import annotations

from types import ModuleType

from . import files, inventory, logs, network, persistence, processes

REGISTRY: dict[str, ModuleType] = {m.NAME: m for m in (inventory, processes, network, persistence, logs, files)}
