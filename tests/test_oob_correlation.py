import unittest
from core.oob_manager import OOBManager

class TestOOBCorrelation(unittest.TestCase):
    def test_correlation_match(self):
        oob = OOBManager()
        oob.token = "test"
        oob.correlation_id = "TANPHA_ABC123"
        oob.set_test_fixture([{"url": "https://target.com/?x=TANPHA_ABC123", "method": "GET"}])
        self.assertTrue(oob.check_hits(None, None))

    def test_correlation_no_match(self):
        oob = OOBManager()
        oob.token = "test"
        oob.correlation_id = "TANPHA_ABC123"
        oob.set_test_fixture([{"url": "https://target.com/?x=OTHER_ID", "method": "GET"}])
        self.assertFalse(oob.check_hits(None, None))

    def test_correlation_empty(self):
        oob = OOBManager()
        oob.token = "test"
        oob.correlation_id = "TANPHA_ABC123"
        oob.set_test_fixture([])
        self.assertFalse(oob.check_hits(None, None))

    def test_correlation_no_id(self):
        oob = OOBManager()
        oob.token = "test"
        oob.correlation_id = None
        oob.set_test_fixture([{"url": "whatever"}])
        self.assertFalse(oob.check_hits(None, None))

if __name__ == "__main__":
    unittest.main()
