"""Background scanner task registry lifecycle tests."""

import asyncio
from uuid import uuid4

import pytest

from webhacking_lab.scanner.jobs import ScanTaskRegistry


@pytest.mark.asyncio
async def test_task_registry_deduplicates_and_cancels_on_shutdown() -> None:
    registry = ScanTaskRegistry()
    started = asyncio.Event()

    async def pending() -> None:
        started.set()
        await asyncio.Event().wait()

    scan_id = uuid4()
    registry.start(scan_id, pending())
    await started.wait()
    duplicate = pending()
    registry.start(scan_id, duplicate)
    assert duplicate.cr_frame is None
    await registry.shutdown()


@pytest.mark.asyncio
async def test_task_registry_shutdown_without_jobs_is_safe() -> None:
    await ScanTaskRegistry().shutdown()
