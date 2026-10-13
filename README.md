# 🛡️ SOC Log Analyzer

A Python-based security log analysis tool designed to help SOC analysts identify suspicious authentication activity, assess risk, and generate actionable security reports.

This project is part of my journey toward building an **AI SOC Analyst** by combining cybersecurity, Python, automation, and eventually AI-assisted security analysis.

---

## 🎯 Project Overview

Security Operations Centers process large volumes of authentication and security logs every day.

Manually reviewing these events can be time-consuming and can cause important threats to be overlooked.

The **SOC Log Analyzer** automates the first stage of this workflow by:

- Parsing security logs
- Detecting suspicious authentication activity
- Applying security detection rules
- Calculating risk
- Prioritizing security events
- Generating analyst-friendly findings
- Producing automated security reports

The current implementation uses deterministic, rule-based detection as the foundation for future AI-assisted analysis.

---

## 🏗️ Architecture

```text
Security Logs
     │
     ▼
Log Parser
     │
     ▼
Event Normalization
     │
     ▼
Detection Rules
     │
     ├── Failed Authentication Detection
     ├── Suspicious Activity Detection
     └── Threshold Analysis
     │
     ▼
Risk Assessment
     │
     ▼
Event Prioritization
     │
     ▼
SOC Findings
     │
     ▼
Security Report
```

---

## 🔎 Key Features

### Log Analysis

Processes security events and extracts relevant information such as:

- Timestamp
- Source IP
- Username
- Authentication result
- Event type
- Failed attempts

### Detection Rules

Identifies suspicious behavior using predefined security rules.

Examples include:

- Multiple failed authentication attempts
- Suspicious login activity
- Authentication anomalies
- Threshold-based detection

### Risk Assessment

Security events are evaluated based on their characteristics and assigned an appropriate risk level.

### Event Prioritization

Security findings can be prioritized so that analysts can focus on the most important events first.

### Automated Reporting

The analyzer generates structured security findings that can be used as the foundation for SOC reporting and analyst investigation.

---

## 🧠 Detection Philosophy

The project follows a simple SOC workflow:

```text
Collect
   ↓
Normalize
   ↓
Detect
   ↓
Assess Risk
   ↓
Prioritize
   ↓
Investigate
```

The goal is not to replace a SOC analyst.

The goal is to **reduce repetitive analysis and help analysts focus on high-value investigations**.

---

## 📊 Example Detection

A simplified example of suspicious authentication activity:

```text
Source IP: 185.199.108.15
Username: admin
Failed Attempts: 35
Event: Multiple Failed Logins
Risk: High
```

The system can identify this activity as suspicious and surface it for further investigation.

---

## 🧪 Testing

The project includes automated tests covering the core detection and analysis functionality.

Run the test suite with:

```bash
python -m unittest discover -s tests -v
```

The tests validate important security-analysis behavior including:

- Detection logic
- Risk assessment
- Authentication analysis
- Event processing
- Report generation
- End-to-end analysis

---

## 📁 Project Structure

```text
soc-log-analyzer/
│
├── data/
│   └── sample_logs
│
├── reports/
│   └── generated_reports
│
├── src/
│   ├── __init__.py
│   └── analyzer.py
│
├── tests/
│   ├── __init__.py
│   └── test_analyzer.py
│
├── main.py
├── requirements.txt
├── README.md
└── LICENSE
```

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/jamese345/soc-log-analyzer.git
```

Move into the project:

```bash
cd soc-log-analyzer
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```bash
.venv\Scripts\activate
```

Run the analyzer:

```bash
python main.py
```

Run the tests:

```bash
python -m unittest discover -s tests -v
```

---

## 🛡️ Security Concepts Demonstrated

This project demonstrates practical SOC concepts including:

- Security log analysis
- Authentication monitoring
- Brute-force detection
- Detection engineering
- Threshold-based detection
- Risk assessment
- Event prioritization
- Security automation
- SOC reporting
- Analyst decision support

---

## 🚀 AI Roadmap

The current version provides a deterministic rule-based foundation.

Future versions will explore AI-assisted capabilities such as:

### Phase 1 — AI Event Classification

Use machine learning or an LLM to classify security events.

### Phase 2 — Analyst Reasoning

Generate natural-language explanations of why an event is suspicious.

### Phase 3 — Threat Context

Combine log information with threat intelligence and additional security context.

### Phase 4 — Investigation Assistance

Generate recommended investigation steps for analysts.

### Phase 5 — AI SOC Integration

Connect the analyzer with the **Automated Alert Triage Engine** and other SOC automation components.

---

## 🔗 Project Evolution

This project is the first stage of my AI SOC development journey.

```text
SOC Log Analyzer
       │
       ▼
Automated Alert Triage Engine
       │
       ▼
AI-Assisted Security Analysis
       │
       ▼
AI SOC Analyst
```

The goal is to progressively combine:

**Cybersecurity + Python + Automation + AI**

into practical SOC capabilities.

---

## 📌 Project Status

**Version:** `v1.0.0`

**Status:** Stable foundation

The rule-based security analysis foundation is complete.

Future development will focus on integrating AI-assisted analysis while maintaining deterministic security rules as a reliable baseline.

---

## 💡 Why This Project Matters

SOC analysts receive large volumes of security events every day.

Automation can help by:

- Reducing repetitive analysis
- Highlighting suspicious activity
- Prioritizing investigations
- Standardizing detection logic
- Providing analysts with useful context

This project demonstrates the first step toward building security systems that can assist analysts rather than simply generating raw alerts.

---

## 👨‍💻 Author

**Brian Owala**

Cybersecurity | Python | Security Automation | AI SOC

Building practical security engineering projects toward becoming an **AI SOC Analyst**.

---

## 📄 License

This project is licensed under the **MIT License**.

