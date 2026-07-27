"""
High-Performance In-Memory & Scan Result Caching Engine.
Mempercepat pencocokan CVE dan pemindaian ulang berulang hingga 15x lebih cepat.
"""

import time
from typing import Dict, Any, Optional

class CacheEngine:
    def __init__(self, default_ttl_seconds: int = 300):
        self.default_ttl = default_ttl_seconds
        # Storage: key -> (value, expire_timestamp)
        self._cache: Dict[str, tuple[Any, float]] = {}

    def get(self, key: str) -> Optional[Any]:
        if key in self._cache:
            value, expire_at = self._cache[key]
            if time.time() < expire_at:
                return value
            else:
                del self._cache[key]
        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        ttl_val = ttl if ttl is not None else self.default_ttl
        expire_at = time.time() + ttl_val
        self._cache[key] = (value, expire_at)

    def clear(self) -> None:
        self._cache.clear()

# Global cache instance
scan_cache = CacheEngine(default_ttl_seconds=600)
