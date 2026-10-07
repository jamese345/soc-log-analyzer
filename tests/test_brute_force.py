import unittest
import pandas as pd

from src.analyzer import detect_brute_force


class TestBruteForce(unittest.TestCase):

    def test_brute_force_detected(self):

        df = pd.DataFrame({
            "src_ip": [
                "10.0.0.1",
                "10.0.0.1",
                "10.0.0.1",
                "10.0.0.1",
                "10.0.0.1"
            ],
            "status": [
                "failed",
                "failed",
                "failed",
                "failed",
                "failed"
            ],
            "timestamp": pd.to_datetime([
                "2026-10-06 10:00:00",
                "2026-10-06 10:01:00",
                "2026-10-06 10:02:00",
                "2026-10-06 10:03:00",
                 "2026-10-06 10:04:00"
                
            ])
        })
       
        alerts = detect_brute_force(df)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "MEDIUM")

        
    def test_no_brute_force(self):

        df = pd.DataFrame({
                "src_ip": [
                    "10.0.0.1",
                    "10.0.0.1",
                    "10.0.0.1",
                    "10.0.0.1",
                
                ],
                "status": [
                    "failed",
                    "failed",
                    "failed",
                    "failed",
                    
                ],
                "timestamp": pd.to_datetime([
                    "2026-10-06 10:00:00",
                    "2026-10-06 10:01:00",
                    "2026-10-06 10:02:00",
                    "2026-10-06 10:03:00",
                    
                ])
            })

        alerts = detect_brute_force(df)

        self.assertEqual(len(alerts), 0)

    

if __name__ == "__main__":
    unittest.main()