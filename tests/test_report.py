import unittest
import pandas as pd

from src.analyzer import generate_soc_report

class TestREPORT(unittest.TestCase):

    def test_report(self):
        alerts = [{
            "rule": "Brute Force",
            "severity": "CRITICAL",
            "risk_score": 90,
            "src_ip": "185.199.108.15",
            "failed_attempts": 35,
            "time_wSindow": "0 days 00:04:32",
            "timestamp": "2026-10-05 09:05:32",
            "recommendation": "Investigate the source IP and review authentication logs.",
        }]

        report = generate_soc_report(alerts)

        self.assertIn("SOC ALERT REPORT", report)
        self.assertIn("Total Alerts: 1", report)
        self.assertIn("Risk Score: 90", report)
        self.assertIn("Recommended Action:", report)

if __name__ == "__main__":
    unittest.main()