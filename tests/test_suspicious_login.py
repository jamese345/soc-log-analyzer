import unittest
import pandas as pd

from src.analyzer import detect_suspicious_login


class TestSuspiciousLogin(unittest.TestCase):

    def test_suspicious_login_detected(self):
        df = pd.DataFrame({
                "src_ip": [
                    "10.0.0.1",
                    "10.0.0.1",
                    "10.0.0.1",
                    "10.0.0.1",
                    
                ],

                "username": [
                    "john",
                    "brian",
                    "james",
                    "mary"
                ],

                "status": [
                    "failed",
                    "failed",
                    "failed",
                    "success",
                                   
                ],

                "timestamp": pd.to_datetime([
                    "2026-10-06 10:00:00",
                    "2026-10-06 10:01:00",
                    "2026-10-06 10:02:00",
                    "2026-10-06 10:03:00",
                   
                ])
            })

        alerts = detect_suspicious_login(df)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "MEDIUM")
        self.assertEqual(alerts[0]["username"], "mary")

if __name__ == "__main__":
    unittest.main()