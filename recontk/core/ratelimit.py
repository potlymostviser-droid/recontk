"""
recontk.core.ratelimit
~~~~~~~~~~~~~~~~~~~~~~~
Token-bucket rate limiter with async and sync interfaces.

Algorithm: classic token bucket.
  - Bucket holds up to ``burst`` tokens.
  - Tokens refill at ``rate`` per second.
  - ``acquire(n)`` blocks/waits until n tokens are available.

Async usage (preferred for tool wrappers)::

    limiter = AsyncTokenBucket(rate=10.0, burst=20)
    async with limiter:          # acquires 1 token
        await run_tool(...)

    await limiter.acquire(5)     # acquires 5 tokens

Sync usage (for native backends running in threads)::

    limiter = SyncTokenBucket(rate=5.0, burst=10)
    with limiter:
        run_tool_sync(...)
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

from recontk.core.errors import RateLimitError

# ---------------------------------------------------------------------------
# Async token bucket
# ---------------------------------------------------------------------------


class AsyncTokenBucket:
    """
    Asyncio-compatible token bucket.

    Parameters
    ----------
    rate:
        Tokens added per second.
    burst:
        Maximum token capacity (also the initial fill level).
    """

    def __init__(self, rate: float, burst: int) -> None:
        if rate <= 0:
            raise ValueError(f"rate must be > 0, got {rate}")
        if burst < 1:
            raise ValueError(f"burst must be >= 1, got {burst}")
        self._rate = rate
        self._burst = float(burst)
        self._tokens: float = float(burst)
        self._last_refill: float = time.monotonic()
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _refill(self) -> None:
        """Add tokens proportional to elapsed time.  Must hold _lock."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        self._last_refill = now

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def acquire(self, tokens: int = 1) -> None:
        """
        Wait until ``tokens`` tokens are available, then consume them.

        Raises
        ------
        ValueError
            If tokens > burst (can never be satisfied).
        """
        if tokens > self._burst:
            raise ValueError(
                f"Requested {tokens} tokens exceeds bucket capacity {self._burst}"
            )
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                # Calculate how long we need to wait for enough tokens
                wait_s = (tokens - self._tokens) / self._rate

            await asyncio.sleep(wait_s)

    async def __aenter__(self) -> "AsyncTokenBucket":
        await self.acquire(1)
        return self

    async def __aexit__(self, *_: Any) -> None:
        pass

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    @property
    def current_tokens(self) -> float:
        """Approximate current token count (not locked; for monitoring only)."""
        return self._tokens

    @property
    def rate(self) -> float:
        return self._rate

    @property
    def burst(self) -> int:
        return int(self._burst)


# ---------------------------------------------------------------------------
# Sync token bucket (thread-safe)
# ---------------------------------------------------------------------------


class SyncTokenBucket:
    """
    Thread-safe synchronous token bucket for use in blocking code paths.

    Parameters
    ----------
    rate:
        Tokens added per second.
    burst:
        Maximum token capacity (also the initial fill level).
    """

    def __init__(self, rate: float, burst: int) -> None:
        if rate <= 0:
            raise ValueError(f"rate must be > 0, got {rate}")
        if burst < 1:
            raise ValueError(f"burst must be >= 1, got {burst}")
        self._rate = rate
        self._burst = float(burst)
        self._tokens: float = float(burst)
        self._last_refill: float = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        self._last_refill = now

    def acquire(self, tokens: int = 1) -> None:
        """Block until ``tokens`` tokens are available."""
        if tokens > self._burst:
            raise ValueError(
                f"Requested {tokens} tokens exceeds bucket capacity {self._burst}"
            )
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                wait_s = (tokens - self._tokens) / self._rate
            time.sleep(wait_s)

    def try_acquire(self, tokens: int = 1) -> bool:
        """Non-blocking acquire.  Returns True if tokens were granted."""
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
        return False

    def __enter__(self) -> "SyncTokenBucket":
        self.acquire(1)
        return self

    def __exit__(self, *_: Any) -> None:
        pass

    @property
    def current_tokens(self) -> float:
        return self._tokens

    @property
    def rate(self) -> float:
        return self._rate

    @property
    def burst(self) -> int:
        return int(self._burst)


# ---------------------------------------------------------------------------
# Factory helper
# ---------------------------------------------------------------------------


def make_limiter_from_config(
    rate: float,
    burst: int,
    *,
    sync: bool = False,
) -> AsyncTokenBucket | SyncTokenBucket:
    """
    Convenience factory used by the runner and tool wrappers.

    Parameters
    ----------
    rate:
        Tokens per second (maps to config.rate_limit.requests_per_second).
    burst:
        Burst capacity (maps to config.rate_limit.burst).
    sync:
        If True, returns a SyncTokenBucket; otherwise AsyncTokenBucket.
    """
    if sync:
        return SyncTokenBucket(rate=rate, burst=burst)
    return AsyncTokenBucket(rate=rate, burst=burst)


# ---------------------------------------------------------------------------
# Unit-test stubs
# ---------------------------------------------------------------------------


def _test_sync_bucket_basic() -> None:
    """SyncTokenBucket: full bucket drains and then enforces rate."""
    bucket = SyncTokenBucket(rate=100.0, burst=5)
    for _ in range(5):
        assert bucket.try_acquire(1), "Should succeed while tokens remain"
    assert not bucket.try_acquire(1), "Should fail when bucket is empty"
    print("ratelimit._test_sync_bucket_basic PASSED")


def _test_sync_bucket_refill() -> None:
    """SyncTokenBucket: tokens refill over time."""
    bucket = SyncTokenBucket(rate=100.0, burst=10)
    # Drain the bucket
    for _ in range(10):
        bucket.try_acquire(1)
    assert not bucket.try_acquire(1)
    # Wait for refill (100 rps → 10 tokens in 0.1 s)
    time.sleep(0.12)
    assert bucket.try_acquire(1), "Bucket should have refilled"
    print("ratelimit._test_sync_bucket_refill PASSED")


async def _test_async_bucket_basic() -> None:
    """AsyncTokenBucket: acquire completes promptly when tokens are available."""
    bucket = AsyncTokenBucket(rate=50.0, burst=5)
    start = time.monotonic()
    for _ in range(5):
        await bucket.acquire(1)
    elapsed = time.monotonic() - start
    assert elapsed < 0.1, f"Drain of full bucket took too long: {elapsed:.3f}s"
    print("ratelimit._test_async_bucket_basic PASSED")


async def _test_async_bucket_throttle() -> None:
    """AsyncTokenBucket: rate-limited acquire takes the expected minimum time."""
    rate = 10.0  # 10 rps → 0.1 s per token
    burst = 1
    bucket = AsyncTokenBucket(rate=rate, burst=burst)
    await bucket.acquire(1)  # drain
    start = time.monotonic()
    await bucket.acquire(1)  # should wait ~0.1 s
    elapsed = time.monotonic() - start
    assert elapsed >= 0.08, f"Rate limit not enforced: elapsed={elapsed:.3f}s"
    print("ratelimit._test_async_bucket_throttle PASSED")


if __name__ == "__main__":
    _test_sync_bucket_basic()
    _test_sync_bucket_refill()
    asyncio.run(_test_async_bucket_basic())
    asyncio.run(_test_async_bucket_throttle())
