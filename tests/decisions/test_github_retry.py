# SPDX-License-Identifier: Apache-2.0
"""Portable deterministic retry contract: no network, credentials or real sleep."""
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci/decisions'))
import github_retry as retry


class Clock:
    def __init__(self):
        self.now, self.epoch, self.delays = 0., 1800000000., []
    def monotonic(self):
        return self.now
    def wall(self):
        return self.epoch
    def sleep(self, delay):
        self.delays.append(delay)
        self.now += delay
    def budget(self, **kwargs):
        return retry.RetryBudget(clock=self.monotonic, wall=self.wall, sleep=self.sleep,
                                 jitter=lambda: .1, **kwargs)


class RetryContract(unittest.TestCase):
    def test_seconds_and_http_date_not_before(self):
        for value in [b'7', format_datetime(datetime.fromtimestamp(1800000007, timezone.utc), usegmt=True).encode()]:
            clock = Clock(); budget = clock.budget()
            self.assertTrue(budget.wait(1, 429, {b'retry-after': value}))
            self.assertEqual(clock.delays, [7.1])
            self.assertGreaterEqual(clock.now, 7)

    def test_primary_reset_and_retry_after_both_respected(self):
        clock = Clock(); budget = clock.budget()
        self.assertTrue(budget.wait(1, 403, {b'x-ratelimit-remaining': b'0',
            b'x-ratelimit-reset': b'1800000010', b'retry-after': b'3'}))
        self.assertEqual(clock.delays, [10.1])

    def test_primary_long_missing_malformed_or_stale_reset_never_sleeps(self):
        for reset in [None, b'invalid PRIVATE_TOKEN', b'1800000000', b'1800003600']:
            clock = Clock(); budget = clock.budget()
            headers = {b'x-ratelimit-remaining': b'0', b'x-ratelimit-reset': reset}
            self.assertFalse(budget.wait(1, 403, headers))
            self.assertEqual(clock.delays, [])
            self.assertNotIn('PRIVATE_TOKEN', budget.reason)

    def test_secondary_403_requires_throttle_or_server_delay(self):
        clock = Clock(); budget = clock.budget()
        self.assertTrue(budget.wait(1, 403, {b'retry-after': b'2'}, 'secondary-rate-limit'))
        self.assertEqual(clock.delays, [2.1])
        for status, category in [(403, 'secondary-rate-limit'), (429, None)]:
            clock = Clock(); budget = clock.budget()
            self.assertFalse(budget.wait(1, status, {}, category))  # >=60s cannot fit45s.
            self.assertEqual(clock.delays, [])

    def test_missing_throttle_header_uses_documented_minimum_with_larger_explicit_budget(self):
        clock = Clock(); budget = clock.budget(total=70)
        self.assertTrue(budget.wait(1, 429))
        self.assertEqual(clock.delays, [60.1])

    def test_permission_denial_and_unrelated_4xx_never_retry(self):
        for status in [301, 400, 401, 403, 404, 409, 422]:
            clock = Clock(); budget = clock.budget()
            self.assertFalse(budget.wait(1, status, {}, 'permission-denied'))
            self.assertEqual(clock.delays, [])

    def test_malformed_duplicate_negative_and_oversized_retry_after_fail_closed(self):
        for value in [None, b'-1', b'1.5', b'nan', b'PRIVATE_TOKEN', b'x' * 129, b'9' * 12,
                      b'Wed, 21 Oct 2015 07:28:00']:
            clock = Clock(); budget = clock.budget()
            self.assertFalse(budget.wait(1, 429, {b'retry-after': value}))
            self.assertEqual(clock.delays, [])

    def test_total_deadline_and_request_timeout_shrink_monotonically(self):
        clock = Clock(); budget = clock.budget(total=5)
        self.assertEqual(budget.remaining(), 5)
        clock.now = 2
        self.assertEqual(budget.remaining(), 3)
        self.assertFalse(budget.wait(1, 503, {b'retry-after': b'3'}))
        self.assertEqual(clock.delays, [])
        clock.now = 5
        with self.assertRaises(retry.RetryDeadline):
            budget.remaining()

    def test_wait_leaves_budget_and_attempts_are_bounded(self):
        clock = Clock(); budget = clock.budget(total=4)
        self.assertTrue(budget.wait(1, 503))
        self.assertTrue(budget.wait(2, 503))
        self.assertFalse(budget.wait(3, 503))
        self.assertEqual(clock.delays, [1.1, 2.1])
        self.assertGreater(budget.remaining(), 0)

    def test_positive_jitter_is_bounded_and_never_subtracts_server_delay(self):
        for injected, expected in [(-100, 2.05), (0, 2.05), (100, 2.25)]:
            clock = Clock(); budget = clock.budget(); budget.jitter = lambda: injected
            self.assertTrue(budget.wait(1, 503, {b'retry-after': b'2'}))
            self.assertEqual(clock.delays, [expected])
        clock = Clock(); budget = clock.budget(); budget.jitter = lambda: float('nan')
        self.assertFalse(budget.wait(1, 503))
        self.assertEqual(clock.delays, [])

    def test_wall_clock_jump_cannot_move_monotonic_deadline(self):
        clock = Clock(); budget = clock.budget()
        clock.epoch += 3600
        self.assertTrue(budget.wait(1, 429, {b'retry-after': b'2'}))
        self.assertEqual(budget.deadline, 45)
        self.assertAlmostEqual(budget.remaining(300), 42.9)

    def test_budget_arguments_and_no_transport_cap_expansion(self):
        for total in [0, -1, float('nan'), float('inf'), 301]:
            with self.assertRaises(ValueError):
                Clock().budget(total=total)
        budget = Clock().budget(total=100)
        self.assertEqual(budget.remaining(), 30)
