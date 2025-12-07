import unittest
from unittest.mock import patch

from utils import validate_ip

class TestNetSpearNetworkAnalyzer(unittest.TestCase):
    def test_validate_ip(self):
        with patch('builtins.input', return_value='y'):
            self.assertTrue(validate_ip("192.168.1.1"))
        self.assertFalse(validate_ip("256.256.256.256"))

if __name__ == "__main__":
    unittest.main()
