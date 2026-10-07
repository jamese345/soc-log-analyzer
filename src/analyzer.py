import pandas as pd

def detect_brute_force(df):
    failed_logins = df[df["status"] == "failed"]
    alerts = []

    for src_ip, group in failed_logins.groupby("src_ip"):
        attempts = len(group)
        difference = group["timestamp"].max() - group["timestamp"].min()

        if len(group) >= 5 and difference <= pd.Timedelta(minutes=5):
            if attempts <= 10:
                severity = "MEDIUM"
            elif attempts <= 20:
                severity = "HIGH"
            else:
                severity = "CRITICAL"

            alert = {
                "rule": "Brute Force",
                "severity": severity,
                "src_ip": src_ip,
                "failed_attempts": attempts,
                "time_window": str(difference),
                "timestamp":group["timestamp"].max()
            }
            alerts.append(alert)

    return alerts


def detect_suspicious_login(df):
    alerts = []

    for src_ip, group in df.groupby("src_ip"):
        successful_logins = group[group["status"] == "success"]

        for _, success in successful_logins.iterrows():
            success_time = success["timestamp"]
            username = success["username"]

            failed_before = group[
                (group["status"] == "failed")
                & (group["timestamp"] >= success_time - pd.Timedelta(minutes=5))
                & (group["timestamp"] < success_time)
            ]
            attempts = len(failed_before)
            if attempts >= 3:
                

                if attempts <= 5:
                    severity = "MEDIUM"
                elif attempts <= 10:
                    severity = "HIGH"
                else:
                    severity = "CRITICAL"

                alert = {
                    "rule": "Suspicious login",
                    "severity": severity,
                    "src_ip": src_ip,
                    "username": username,
                    "failed_attempts": attempts,
                    "time_window": "5 minutes",
                    "status": "success",
                    "timestamp":success_time
                }

                alerts.append(alert)     

    return alerts

def detect_multiple_users(df):
    alerts = []

    for src_ip, group in df.groupby("src_ip"):
        unique_users = group["username"].nunique()
        if unique_users >= 3:
            if unique_users <= 5:
                severity = "MEDIUM"
            elif unique_users <= 10:
                severity = "HIGH"
            else:
                severity = "CRITICAL"

            alert = {
                "rule": "Multiple Users From One IP",
                "severity": severity,
                "src_ip": src_ip,
                "unique_users": unique_users,
                "timestamp": group["timestamp"].max(),
            }

            alerts.append(alert)

    return alerts

def deduplicate_alerts(alerts):
    unique_alerts = []
    seen = set()

    for alert in alerts:
        key = (
            alert["rule"],
            alert["src_ip"],
            alert.get("username"),
            alert["timestamp"]
        )

        if key not in seen:
            seen.add(key)
            unique_alerts.append(alert)

    return unique_alerts


def calculate_risk_score(alert):

    if alert["severity"] == "MEDIUM":
        return 40
    elif alert["severity"] == "HIGH":
        return 70
    else:
        return 90

def generate_recommendation(alert):
    if alert["rule"] == "Brute Force":
        return "Investigate the source IP and review authentication logs."

    elif alert["rule"] == "Suspicious login":
        return "Investigate the successful login and verify the user's identity."

    elif alert["rule"] == "Multiple Users From One IP":
        return "Investigate the source IP and determine whether multiple accounts are being targeted."

    return "Investigate the alert and review related security logs."


def prioritize_alerts(alerts):
    return sorted(alerts, key=lambda alert: alert["risk_score"], reverse=True)


def determine_overall_severity(alerts):
    highest_risk = max((alert["risk_score"] for alert in alerts), default=0)
   
    
    if highest_risk == 90:
        return "CRITICAL"
        
    elif highest_risk == 70:
        return "HIGH"
        
    elif highest_risk == 40:
        return "MEDIUM"
       
    else:
        return "LOW"

def generate_alert_summary(alerts):
    critical = sum(1 for alert in alerts if alert["severity"] == "CRITICAL")
    high = sum(1 for alert in alerts if alert["severity"] == "HIGH")
    medium = sum(1 for alert in alerts if alert["severity"] == "MEDIUM")
    highest_risk = max((alert["risk_score"] for alert in alerts), default=0)
    return {
        "critical": critical,
        "high": high,
        "medium": medium,
        "highest_risk": highest_risk,
    }


def generate_soc_report(alerts):
    summary = generate_alert_summary(alerts)
    overall_severity = determine_overall_severity(alerts)
    report = ""

    report += "========================================\n"
    report += "           SOC ALERT REPORT\n"
    report += "========================================\n"
    report += f"\nTotal Alerts: {len(alerts)}\n\n"
    report += f"Critical: {summary['critical']}\n"
    report += f"High: {summary['high']}\n"
    report += f"Medium: {summary['medium']}\n"
    report += f"Highest Risk Score: {summary['highest_risk']}\n\n"
    report += f"Overall Severity: {overall_severity}\n\n"


    for number, alert in enumerate(alerts, start=1):
        report += f"ALERT #{number}\n"
        report += f"Rule: {alert['rule']}\n"
        report += f"Severity: {alert['severity']}\n"
        report += f"Risk Score: {alert['risk_score']}\n"
        report += f"Source IP: {alert['src_ip']}\n"
        if "failed_attempts" in alert:
            report += f"Failed Attempts: {alert['failed_attempts']}\n"
        if "time_window" in alert:
            report += f"Time Window: {alert['time_window']}\n"
        if "unique_users" in alert:
            report += f"Unique Users: {alert['unique_users']}\n"
        report += f"Timestamp: {alert['timestamp']}\n"
        report += f"Recommended Action: {alert['recommendation']}\n"

        ioc = extract_ioc(alert)
        

        report += f"IOC TYPE: {ioc['type']}\n"
        report += f"IOC VALUE: {ioc['value']}\n"



        if "username" in alert:
            report += f"Username: {alert['username']}\n"
        report += "\n"

    return report

def extract_ioc(alert):
    if "src_ip" in alert and alert["src_ip"]:
        return {
            "type": "IP Address",
            "value": alert["src_ip"]
        }

    return {
        "type": "Unknown",
        "value": "Unknown"
    }