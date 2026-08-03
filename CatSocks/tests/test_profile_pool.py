import unittest
from core.profile_pool import ProfilePool


class ProfilePoolTests(unittest.TestCase):
    def test_fifo_nine_profiles(self):
        pool = ProfilePool(range(9))
        allocated = [pool.acquire() for _ in range(9)]
        self.assertEqual(allocated, list(range(9)))
        with self.assertRaises(RuntimeError):
            pool.acquire()
        pool.release(0)
        pool.release(1)
        self.assertEqual(pool.acquire(), 0)
        self.assertEqual(pool.acquire(), 1)


if __name__ == "__main__":
    unittest.main()
