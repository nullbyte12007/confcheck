"""Registry aturan: auto-register lewat subclass."""
from __future__ import annotations

import importlib
import pkgutil

ALL_RULES: list[type] = []


class Rule:
    CODE = "?"
    TITLE = ""
    CATEGORY = "umum"
    PLATFORMS = {"cisco-ios", "mikrotik-routeros"}

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        if getattr(cls, "CODE", "?") != "?":
            ALL_RULES.append(cls)

    def run(self, dev) -> list:
        raise NotImplementedError


def load_all() -> None:
    """Impor semua modul aturan supaya terdaftar (aman dipanggil berulang —
    importlib meng-cache modul, jadi __init_subclass__ tidak jalan dua kali)."""
    import confcheck.rules as pkg
    for info in pkgutil.iter_modules(pkg.__path__):
        if info.name.startswith("_"):
            continue
        importlib.import_module(f"confcheck.rules.{info.name}")


def select(platform: str, only=None, skip=None) -> list[type]:
    out = []
    for cls in ALL_RULES:
        if platform not in cls.PLATFORMS:
            continue
        if only and cls.CODE not in only and cls.CATEGORY not in only:
            continue
        if skip and (cls.CODE in skip or cls.CATEGORY in skip):
            continue
        out.append(cls)
    return sorted(out, key=lambda c: (c.CATEGORY, c.CODE))


def describe() -> list[tuple[str, str, str]]:
    return [(c.CODE, c.CATEGORY, c.TITLE)
            for c in sorted(ALL_RULES, key=lambda c: (c.CATEGORY, c.CODE))]
