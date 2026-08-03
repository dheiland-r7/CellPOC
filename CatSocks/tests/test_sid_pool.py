import threading
import unittest

from core.sid_pool import SidPool


class SidPoolTests(unittest.TestCase):
    def test_fifo_rotation_matches_v00702(self):
        pool = SidPool(range(3))
        self.assertEqual(pool.acquire(), 0)
        pool.release(0)
        self.assertEqual(pool.acquire(), 1)
        self.assertEqual(pool.acquire(), 2)
        self.assertEqual(pool.acquire(), 0)

    def test_duplicate_release_is_ignored(self):
        pool = SidPool(range(2))
        sid = pool.acquire()
        self.assertTrue(pool.release(sid))
        self.assertFalse(pool.release(sid))
        self.assertEqual(pool.snapshot(), [1, 0])

    def test_exhaustion_fast_fails(self):
        pool = SidPool([0])
        self.assertEqual(pool.acquire(), 0)
        with self.assertRaisesRegex(RuntimeError, "No socket IDs available"):
            pool.acquire()

    def test_unknown_sid_is_rejected(self):
        pool = SidPool(range(2))
        with self.assertRaisesRegex(ValueError, "Unknown socket ID"):
            pool.release(9)

    def test_concurrent_allocations_are_unique(self):
        pool = SidPool(range(10))
        barrier = threading.Barrier(10)
        results = []
        lock = threading.Lock()

        def worker():
            barrier.wait()
            sid = pool.acquire()
            with lock:
                results.append(sid)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(sorted(results), list(range(10)))


class SidPoolQuarantineTests(unittest.TestCase):
    def test_quarantined_sid_is_not_reallocated(self):
        pool = SidPool(range(2))
        sid0 = pool.acquire()
        pool.quarantine(sid0, "uncertain modem state")

        self.assertEqual(pool.acquire(), 1)
        with self.assertRaises(RuntimeError):
            pool.acquire()
        self.assertTrue(pool.is_quarantined(0))

    def test_recovered_sid_returns_to_fifo_tail(self):
        pool = SidPool(range(3))
        sid0 = pool.acquire()
        pool.quarantine(sid0, "test")
        sid1 = pool.acquire()
        pool.release(sid1)
        pool.recover(sid0)

        self.assertEqual(pool.snapshot(), [2, 1, 0])

    def test_release_does_not_bypass_quarantine(self):
        pool = SidPool(range(1))
        sid = pool.acquire()
        pool.quarantine(sid, "test")

        self.assertFalse(pool.release(sid))
        self.assertEqual(pool.snapshot(), [])


if __name__ == "__main__":
    unittest.main()
