"""Process-wide fail-fast request rate and concurrency limits."""

import asyncio
from collections import defaultdict, deque
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from time import monotonic

from webhacking_lab.domain.exceptions import RateLimitError


class RequestGate:
    """Enforce global/target rolling-minute limits and target concurrency."""

    def __init__(self, clock: Callable[[], float] = monotonic) -> None:
        self._clock = clock
        self._lock = asyncio.Lock()
        self._global: deque[float] = deque()
        self._targets: dict[str, deque[float]] = defaultdict(deque)
        self._active: dict[str, int] = defaultdict(int)

    @staticmethod
    def _prune(values: deque[float], threshold: float) -> None:
        while values and values[0] <= threshold:
            values.popleft()

    async def acquire(
        self,
        target_key: str,
        *,
        global_per_minute: int,
        target_per_minute: int,
        max_concurrency: int,
    ) -> None:
        """Reserve one request slot or fail without queueing hidden traffic."""

        async with self._lock:
            now = self._clock()
            threshold = now - 60
            target = self._targets[target_key]
            self._prune(self._global, threshold)
            self._prune(target, threshold)
            if len(self._global) >= global_per_minute:
                raise RateLimitError("Global request rate limit reached; try again later")
            if len(target) >= target_per_minute:
                raise RateLimitError("Target request rate limit reached; try again later")
            if self._active[target_key] >= max_concurrency:
                raise RateLimitError("Target concurrency limit reached; try again later")
            self._global.append(now)
            target.append(now)
            self._active[target_key] += 1

    async def release(self, target_key: str) -> None:
        """Release a target concurrency slot."""

        async with self._lock:
            self._active[target_key] = max(0, self._active[target_key] - 1)

    @asynccontextmanager
    async def slot(
        self,
        target_key: str,
        *,
        global_per_minute: int,
        target_per_minute: int,
        max_concurrency: int,
    ) -> AsyncIterator[None]:
        """Guard a single outbound request with an automatically released slot."""

        await self.acquire(
            target_key,
            global_per_minute=global_per_minute,
            target_per_minute=target_per_minute,
            max_concurrency=max_concurrency,
        )
        try:
            yield
        finally:
            await self.release(target_key)
