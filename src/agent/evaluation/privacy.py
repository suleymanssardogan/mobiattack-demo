"""Reject unsafe fixtures; never persist rejected model prose or raw responses."""
import re
from src.agent.models import ContractError

UNSAFE_FIELDS = frozenset({"authorization", "cookie", "cookies", "token", "access_token", "refresh_token",
    "password", "credentials", "api_key", "secret", "headers", "body", "raw_body", "raw_logs",
    "source_file", "filesystem_path", "chain_of_thought", "reasoning"})
UNSAFE_TEXT = re.compile(r"(?:\bBearer\s+\S+|\bBasic\s+[A-Za-z0-9+/=]+|\bsk-[A-Za-z0-9_-]{8,}|\b(?:password|api_key|token|cookie)\s*[=:]\s*\S+)", re.I)


def unsafe_text(value):
    return isinstance(value, str) and (bool(UNSAFE_TEXT.search(value))
        or any(prefix in value for prefix in ("/Users/", "/home/", "/private/", "/tmp/", "/etc/", "file://")) or bool(re.search(r"[A-Za-z]:\\", value)))


def validate_privacy(value, depth=0, budget=None):
    budget = [4096] if budget is None else budget
    budget[0] -= 1
    if depth > 12 or budget[0] < 0:
        raise ContractError("Privacy input exceeds bound")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or key.lower() in UNSAFE_FIELDS:
                raise ContractError("Unsafe fixture/report field")
            validate_privacy(child, depth + 1, budget)
    elif isinstance(value, (list, tuple)):
        for child in value: validate_privacy(child, depth + 1, budget)
    elif isinstance(value, str):
        if len(value) > 2048 or unsafe_text(value):
            raise ContractError("Unsafe fixture/report value")
    elif value is not None and type(value) not in (bool, int, float):
        raise ContractError("Invalid fixture/report value")
