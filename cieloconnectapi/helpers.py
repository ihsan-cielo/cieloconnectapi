import math
import random
from typing import Any, Optional

def _to_int(v: Any, *, default: Optional[int] = None) -> Optional[int]:
    try:
        return int(v)
    except Exception:
        return default


def _to_float(v: Any, *, default: Optional[float] = None) -> Optional[float]:
    try:
        f = float(v)
        if math.isnan(f) or math.isinf(f):
            return default
        return f
    except Exception:
        return default


def _to_str_or_none(v: Any) -> Optional[str]:
    s = str(v).strip() if v is not None else None
    return s or None


def _exp_backoff(attempt: int) -> float:
    base = min(8.0, 0.5 * (2**attempt))
    return base + random.uniform(0.0, 0.25 * base)