from __future__ import annotations
from dataclasses import dataclass
import os

def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default)

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default

def parse_allowed_chat_ids(raw: str) -> set[int]:
    out: set[int] = set()
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.add(int(part))
        except ValueError:
            pass
    return out

def parse_save_targets(raw: str) -> list[tuple[str, str]]:
    """
    Format: LABEL:/path|LABEL:/path|...
    Zwraca listę (label, path) w kolejności → będą to opcje 1..N.
    """
    targets: list[tuple[str, str]] = []
    for chunk in (raw or "").split("|"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if ":" not in chunk:
            continue
        label, path = chunk.split(":", 1)
        label = label.strip()
        path = path.strip()
        if label and path:
            targets.append((label, path))
    return targets

@dataclass(frozen=True)
class Config:
    bot_token: str
    allowed_chat_ids: set[int]
    save_targets: list[tuple[str, str]]
    max_results: int

    @staticmethod
    def from_env() -> "Config":
        token = _env("BOT_TOKEN")
        if not token:
            raise RuntimeError("Missing BOT_TOKEN in .env")

        allowed = parse_allowed_chat_ids(_env("ALLOWED_CHAT_IDS", ""))
        targets = parse_save_targets(_env("SAVE_TARGETS", ""))

        if not targets:
            raise RuntimeError("SAVE_TARGETS is empty or invalid (expected LABEL:/path|...)")

        return Config(
            bot_token=token,
            allowed_chat_ids=allowed,
            save_targets=targets,
            max_results=_env_int("MAX_RESULTS", 10),
        )
