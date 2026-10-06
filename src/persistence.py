"""Shared filesystem persistence; domain validation belongs to the caller."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any


def write_json_atomic(path: str | Path, data: Any, *, durable: bool = False,
                      allow_nan: bool = True) -> Path:
    """Replace a JSON artifact only after serialization succeeds.

    A unique temporary file in the destination directory preserves atomic rename
    semantics. Failure leaves the previous artifact intact and removes scratch data.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=target.parent, prefix='.tmp_json_', suffix='.json')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False, allow_nan=allow_nan)
            if durable:
                stream.flush()
                os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return target
