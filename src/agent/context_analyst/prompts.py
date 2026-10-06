"""Versioned application instruction asset; correction contains no rejected output."""
from pathlib import Path

from .models import PROMPT_VERSION

INSTRUCTION = Path(__file__).with_name("context_analyst_compact_v1.txt").read_text(encoding="utf-8")
RETRY_CORRECTION = "Previous output violated schema. Return only valid structured output."
