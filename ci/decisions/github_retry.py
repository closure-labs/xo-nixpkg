# SPDX-License-Identifier: Apache-2.0
"""Bounded GET retry policy. Contains no credentials, bodies or authority cache."""
from email.utils import parsedate_to_datetime
import math
import random
import re
import time


class RetryDeadline(ValueError):
    """A fresh request cannot fit the monotonic retry budget."""


def number(value):
    if isinstance(value, bytes) and re.fullmatch(rb'[0-9]{1,11}', value):
        return int(value)
    return None


def retry_after(value, now):
    """HTTP delay-seconds or an aware HTTP-date; malformed is never clamped."""
    seconds = number(value)
    if seconds is not None:
        return float(seconds)
    if not isinstance(value, bytes) or len(value) > 128:
        return None
    try:
        date = parsedate_to_datetime(value.decode('ascii'))
        if date.tzinfo is None:
            return None
        return max(0.0, date.timestamp() - now)
    except (ValueError, TypeError, OverflowError, UnicodeError):
        return None


class RetryBudget:
    """At most three attempts/45 seconds, also bounded by the caller's budget.

    Wall-clock headers become delays against one wall/monotonic anchor. Later
    wall-clock jumps cannot extend the total deadline. A server not-before delay
    is a minimum, never shortened to fit a budget. Long waits fail closed so the
    scheduler can retry after reset. Only fresh GETs may use this helper.
    """
    def __init__(self, total=45.0, attempts=3, *, clock=None, wall=None, sleep=None, jitter=None):
        if not math.isfinite(total) or not 0 < total <= 300 or type(attempts) is not int or not 1 <= attempts <= 3:
            raise ValueError('Invalid retry budget')
        self.clock = clock or time.monotonic
        self.sleep = sleep or time.sleep
        self.jitter = jitter or (lambda: random.SystemRandom().uniform(.05, .25))
        self.start = self.clock()
        self.epoch = (wall or time.time)()
        self.deadline, self.attempts = self.start + total, attempts
        self.reason = None

    def remaining(self, cap=30.0):
        remaining = min(cap, self.deadline - self.clock())
        if remaining <= 0:
            raise RetryDeadline('GitHub GET retry deadline exhausted')
        return remaining

    def wait(self, attempt, status=None, headers=None, category=None):
        if type(attempt) is not int or not 1 <= attempt <= self.attempts:
            raise ValueError('Invalid GET retry attempt')
        headers = headers or {}
        if status == 403 and category == 'permission-denied':
            self.reason = 'not-retryable'
            return False
        if attempt >= self.attempts:
            self.reason = 'attempt-limit'
            return False
        now = self.epoch + self.clock() - self.start
        after_present = b'retry-after' in headers
        after = retry_after(headers.get(b'retry-after'), now)
        if after_present and after is None:
            self.reason = 'invalid-not-before'
            return False
        primary = status in (403, 429) and headers.get(b'x-ratelimit-remaining') == b'0'
        secondary = category in ('secondary-rate-limit', 'rate-limit')
        if status == 403 and not (primary or secondary or after is not None):
            self.reason = 'not-retryable'
            return False
        if status not in (None, 403, 408, 429, 500, 502, 503, 504):
            self.reason = 'not-retryable'
            return False
        delay = float(2 ** (attempt - 1))
        if primary:
            reset = number(headers.get(b'x-ratelimit-reset'))
            if reset is None or reset <= now:
                self.reason = 'missing-or-stale-reset'
                return False
            delay = max(delay, reset - now)
        if after is not None:
            delay = max(delay, after)
        elif status == 429 or secondary:
            # GitHub's documented fallback for secondary throttling is >=60s.
            delay = max(delay, 60.0)
        jitter = self.jitter()
        if not isinstance(jitter, (int, float)) or not math.isfinite(jitter):
            self.reason = 'invalid-jitter'
            return False
        delay += min(.25, max(.05, jitter))
        if delay + .01 >= self.remaining(300):
            self.reason = 'not-before-exceeds-budget'
            return False
        self.sleep(delay)
        self.remaining()
        self.reason = 'retry-fresh-get'
        return True
