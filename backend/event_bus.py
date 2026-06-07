"""
event_bus.py – AsyncIO-based publish/subscribe event bus.

Provides a thread-safe, singleton event bus that allows coroutines to
publish messages onto named channels and subscribe callbacks to receive
them in real time.

Channels
--------
- ``events``    – Normalized security events
- ``alerts``    – Generated alert objects
- ``network``   – Network connection snapshots
- ``firewall``  – Firewall log events
- ``resource``  – Resource-usage metrics

Usage
-----
::

    from backend.event_bus import event_bus

    async def my_handler(data):
        print(data)

    event_bus.subscribe("alerts", my_handler)
    await event_bus.publish("alerts", {"title": "test"})
    event_bus.unsubscribe("alerts", my_handler)
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)

# Type alias for subscriber callbacks
Callback = Callable[[Any], Coroutine[Any, Any, None]]

# Pre-defined channels (new channels can still be created on-the-fly)
CHANNELS = frozenset({"events", "alerts", "network", "firewall", "resource"})


class EventBus:
    """Async pub/sub message bus with per-channel subscriptions."""

    def __init__(self) -> None:
        # channel -> ordered list of callbacks
        self._subscribers: dict[str, list[Callback]] = defaultdict(list)
        # Protects subscriber list mutations
        self._lock = asyncio.Lock()
        logger.info("EventBus created.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def subscribe(self, channel: str, callback: Callback) -> None:
        """Register *callback* to receive messages on *channel*."""
        async with self._lock:
            if callback not in self._subscribers[channel]:
                self._subscribers[channel].append(callback)
                logger.debug(
                    "Subscribed %s to channel '%s' (%d total)",
                    callback.__qualname__,
                    channel,
                    len(self._subscribers[channel]),
                )

    async def unsubscribe(self, channel: str, callback: Callback) -> None:
        """Remove *callback* from *channel*."""
        async with self._lock:
            try:
                self._subscribers[channel].remove(callback)
                logger.debug(
                    "Unsubscribed %s from channel '%s'",
                    callback.__qualname__,
                    channel,
                )
            except ValueError:
                logger.warning(
                    "Attempted to unsubscribe %s from '%s' but it was not registered.",
                    callback.__qualname__,
                    channel,
                )

    async def publish(self, channel: str, data: Any) -> None:
        """Broadcast *data* to all subscribers of *channel*.

        Each callback is invoked concurrently via ``asyncio.gather``.
        A failing callback logs the error but does not prevent others from
        receiving the message.
        """
        async with self._lock:
            callbacks = list(self._subscribers.get(channel, []))

        if not callbacks:
            return

        logger.debug(
            "Publishing to '%s' – %d subscriber(s)", channel, len(callbacks)
        )

        results = await asyncio.gather(
            *(self._safe_call(cb, data) for cb in callbacks),
            return_exceptions=True,
        )

        for idx, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    "Subscriber %s on '%s' raised %s: %s",
                    callbacks[idx].__qualname__,
                    channel,
                    type(result).__name__,
                    result,
                )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    async def _safe_call(callback: Callback, data: Any) -> None:
        """Invoke *callback* with *data*, catching exceptions."""
        try:
            await callback(data)
        except Exception:
            # Re-raise so gather() captures it as a returned exception
            raise

    def subscriber_count(self, channel: str) -> int:
        """Return the current number of subscribers on *channel*."""
        return len(self._subscribers.get(channel, []))

    def channels(self) -> list[str]:
        """Return all channels that have at least one subscriber."""
        return [ch for ch, subs in self._subscribers.items() if subs]

    async def clear(self) -> None:
        """Remove all subscriptions – useful during shutdown."""
        async with self._lock:
            self._subscribers.clear()
            logger.info("EventBus cleared all subscriptions.")


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
event_bus = EventBus()
