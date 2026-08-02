"""Application-owned lifecycle for background scan tasks."""

import asyncio
from collections.abc import Coroutine
from typing import Any
from uuid import UUID


class ScanTaskRegistry:
    """Track bounded background jobs and cancel them during application shutdown."""

    def __init__(self) -> None:
        self._tasks: dict[UUID, asyncio.Task[None]] = {}

    def start(self, scan_id: UUID, operation: Coroutine[Any, Any, None]) -> None:
        """Start one task per persisted scan identifier."""

        current = self._tasks.get(scan_id)
        if current is not None and not current.done():
            operation.close()
            return
        task = asyncio.create_task(operation, name=f"passive-scan-{scan_id}")
        self._tasks[scan_id] = task
        task.add_done_callback(lambda _task: self._tasks.pop(scan_id, None))

    async def shutdown(self) -> None:
        """Cancel remaining jobs before the database engine is disposed."""

        tasks = list(self._tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()
