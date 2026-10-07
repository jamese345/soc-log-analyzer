import pandas as pd
from tkinter import filedialog
import tkinter as tk
import os

from src.analyzer import (
    detect_brute_force,
    detect_suspicious_login,
    detect_multiple_users,
    deduplicate_alerts,
    calculate_risk_score,
    generate_recommendation,
    prioritize_alerts,
    generate_soc_report,
)


root = tk.Tk() 
root.withdraw() 

file_path = filedialog.askopenfilename(
        title="Select log file", 
        filetypes=[ ("CSV files", "*.csv"), 
                ("JSON files", "*.json"), 
        ])  

if not file_path: 
    print("No file selected.") 
    exit() 

try:
        if file_path.lower().endswith(".csv"): 
                df=pd.read_csv(file_path) 

        elif file_path.lower().endswith(".json"):              
                df=pd.read_json(file_path) 

        else: 
                print("Unsupported file type.") 
                exit() 
except Exception as e:
      print(f"Error reading log file: {e}")
      exit()

required_columns = [
    "src_ip",
    "username",
    "status",
    "timestamp"
]

missing_columns = [
    column for column in required_columns
    if column not in df.columns
]

if missing_columns:
    print(f"Missing required columns: {missing_columns}")
    exit()

if len(df) == 0:
        print("Log file contains no events.")
        exit()

df["status"] = df["status"].replace({
    "FAILED": "failed",
    "failure": "failed",
    "SUCCESS": "success",
    "SUCCESSFUL": "success",
    "unknown": "unknown"
})

invalid_statuses = df[
    ~df["status"].isin({
        "failed",
        "success",
        "unknown"
    })
]
invalid_values = invalid_statuses["status"].unique()

if len(invalid_statuses) > 0:
        print(f"Invalid status values found in log file: {invalid_values}")
        exit()


print("===== SOC LOG SUMMARY =====")
print(f"Total events: {len(df)}")
print(f"Unique IPs: {df['src_ip'].nunique()}")
print(f"Unique users: {df['username'].nunique()}")
print("\nEvents:")
print(df["status"].value_counts()) 

                
df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    errors="coerce"
)
if df["timestamp"].isna().any():
      print("Invalid timestamps found in log file.")
      exit()

df = df.sort_values("timestamp") 


brute_force_alerts = detect_brute_force(df)
suspicious_alerts = detect_suspicious_login(df)
multiple_users_alerts = detect_multiple_users(df)

all_alerts = brute_force_alerts + suspicious_alerts + multiple_users_alerts
all_alerts = deduplicate_alerts(all_alerts)

print("Total alerts:", len(all_alerts))
print("\n")

for alert in all_alerts:
    alert["risk_score"] = calculate_risk_score(alert)
    alert["recommendation"] = generate_recommendation(alert)

prioritized_alerts = prioritize_alerts(all_alerts)

report_dir = "reports"
os.makedirs(report_dir, exist_ok=True)

with open(os.path.join(report_dir, "soc_report.txt"), "w") as file:
    file.write(generate_soc_report(prioritized_alerts))