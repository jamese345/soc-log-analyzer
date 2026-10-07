import unittest
import pandas as pd

from src.analyzer import detect_multiple_users


class TestMultipleUsers(unittest.TestCase):

    def test_multiple_users_detected(self):
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
        
            "timestamp": pd.to_datetime([
                "2026-10-06 10:00:00",
                "2026-10-06 10:01:00",
                "2026-10-06 10:02:00",
                "2026-10-06 10:03:00",
                           
            ])
        })

        alerts = detect_multiple_users(df)
        
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "MEDIUM")
        self.assertEqual(alerts[0]["unique_users"], 4)

if __name__ == "__main__":
    unittest.main()
        