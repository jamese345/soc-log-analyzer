import unittest
from src.analyzer import calculate_risk_score

class TestRiskScore(unittest.TestCase):

    def test_medium_risk(self):
        alert = {
            "severity": "MEDIUM"
        }

        result = calculate_risk_score(alert)

        self.assertEqual(result, 40)

    def test_high_risk(self):
        alert = {
            "severity": "HIGH"
        }
        
        result = calculate_risk_score(alert)
        
        self.assertEqual(result, 70)
        

    def test_critical_risk(self):
        alert = {
            "severity": "CRITICAL"
        }
         
        result = calculate_risk_score(alert)
         
        self.assertEqual(result, 90)