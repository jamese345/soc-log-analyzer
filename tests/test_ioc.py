import unittest

from src.analyzer import extract_ioc


class TestIOC(unittest.TestCase):

    def test_extract_ip_ioc(self):
        alert = {
            "src_ip": "185.199.108.15"
        }

        ioc = extract_ioc(alert)

        self.assertEqual(ioc["type"], "IP Address")
        self.assertEqual(ioc["value"], "185.199.108.15")

    def test_missing_ioc(self):
        alert = {
            "rule": "Test Alert"
    }

        ioc = extract_ioc(alert)

        self.assertEqual(ioc["type"], "Unknown")
        self.assertEqual(ioc["value"], "Unknown")


if __name__ == "__main__":
    unittest.main()