"""Fault injection for cleanup; no Docker or native confinement claim."""

import unittest
from unittest.mock import AsyncMock

from examples.confinement.adapter import Refused

from tests.confinement.cleanup import remove_if_present


class CleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_already_absent_does_not_remove(self):
        observer = AsyncMock()
        observer.docker.return_value = b"other-container\n"
        await remove_if_present(observer, "target")
        self.assertEqual(observer.docker.await_count, 1)

    async def test_successful_removal_requires_observed_absence(self):
        observer = AsyncMock()
        observer.docker.side_effect = [b"target\n", b"", b""]
        await remove_if_present(observer, "target")
        self.assertEqual(observer.docker.await_args_list[1].args, ("rm", "--force", "target"))
        self.assertEqual(observer.docker.await_count, 3)

    async def test_concurrent_removal_is_accepted_after_recheck(self):
        observer = AsyncMock()
        observer.docker.side_effect = [b"target\n", Refused("Docker operation failed"), b""]
        await remove_if_present(observer, "target")
        self.assertEqual(observer.docker.await_count, 3)

    async def test_failed_removal_with_survivor_preserves_original_error(self):
        observer = AsyncMock()
        error = Refused("Docker operation failed")
        observer.docker.side_effect = [b"target\n", error, b"target\n"]
        with self.assertRaises(Refused) as raised:
            await remove_if_present(observer, "target")
        self.assertIs(raised.exception, error)

    async def test_successful_command_with_survivor_is_refused(self):
        observer = AsyncMock()
        observer.docker.side_effect = [b"target\n", b"", b"target\n"]
        with self.assertRaisesRegex(Refused, "cleanup incomplete"):
            await remove_if_present(observer, "target")

    async def test_listing_errors_are_not_treated_as_absence(self):
        for responses in (
            [Refused("Docker unavailable")],
            [b"target\n", Refused("Docker operation failed"), Refused("Docker unavailable")],
            [b"target\n", b"", Refused("Docker unavailable")],
        ):
            with self.subTest(responses=responses):
                observer = AsyncMock()
                observer.docker.side_effect = responses
                with self.assertRaisesRegex(Refused, "Docker unavailable"):
                    await remove_if_present(observer, "target")

    async def test_cancellation_is_not_swallowed(self):
        import asyncio

        observer = AsyncMock()
        observer.docker.side_effect = [b"target\n", asyncio.CancelledError()]
        with self.assertRaises(asyncio.CancelledError):
            await remove_if_present(observer, "target")
        self.assertEqual(observer.docker.await_count, 2)
