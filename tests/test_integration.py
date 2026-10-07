import unittest
import pandas as pd

from src.analyzer import (
    detect_brute_force,
    detect_suspicious_login,
    detect_multiple_users,
    calculate_risk_score,
    deduplicate_alerts,
    prioritize_alerts,
    generate_soc_report,
    generate_recommendation,
    
)

class TestSOCIntegration(unittest.TestCase):

    def test_full_pipeline(self):
        df = pd.DataFrame({
                        "src_ip": [
                            "10.0.0.50",
                            "10.0.0.50",
                            "10.0.0.50",
                            "10.0.0.50",
                            "10.0.0.50",
                            "10.0.0.50"
                            
                        ],
        
                        "username": [
                            "john",
                            "brian",
                            "james",
                            "mary",
                            "joana",
                            "alex"
                        ],
        
                        "status": [
                            "failed",
                            "failed",
                            "failed",
                            "success",
                            "failed",
                            "failed"
        
                                           
                        ],
        
                        "timestamp": pd.to_datetime([
                            "2026-10-06 10:00:00",
                            "2026-10-06 10:01:00",
                            "2026-10-06 10:02:00",
                            "2026-10-06 10:03:00",
                            "2026-10-06 10:04:00",
                            "2026-10-06 10:05:00"

                           
                ])
            })

        brute_force_alerts = detect_brute_force(df)
        suspicious_alerts = detect_suspicious_login(df)
        multiple_users_alerts = detect_multiple_users(df)

        all_alerts = (
            brute_force_alerts
            + suspicious_alerts
            + multiple_users_alerts
        )

        self.assertEqual(len(brute_force_alerts), 1)
        self.assertEqual(len(suspicious_alerts), 1)
        self.assertEqual(len(multiple_users_alerts), 1)

        self.assertEqual(len(all_alerts), 3)

        all_alerts = deduplicate_alerts(all_alerts)

        self.assertEqual(len(all_alerts), 3)

        for alert in all_alerts:
            alert["risk_score"] = calculate_risk_score(alert)
            alert["recommendation"] = generate_recommendation(alert)

        for alert in all_alerts:
            self.assertIn("risk_score", alert)

        prioritized_alerts = prioritize_alerts(all_alerts)

        self.assertEqual(
                prioritized_alerts[0]["risk_score"],
                max(alert["risk_score"] for alert in all_alerts)
        )

        report = generate_soc_report(prioritized_alerts)

        self.assertIn("SOC ALERT REPORT", report)
        self.assertIn("Total Alerts: 3", report)
        self.assertIn("Risk Score:", report)
        self.assertIn("Recommended Action:", report)

if __name__ == "__main__":
    unittest.main()

