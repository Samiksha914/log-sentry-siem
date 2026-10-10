# 🛡️ LogSentry SIEM: Automated Intrusion Detection Engine

`log-sentry-siem` is a localized log auditing and behavioral alert parser written in Python. It scans system authentication logs, leverages regular expression extraction matrix rules, tracks statistical anomaly thresholds, and flags brute-force attack vectors targeting core host services.

## 📦 Project Directory
- `log_sentry.py`: The analytical execution script processing unstructured security logs.
- `os-security-notes.md`: Detailed engineering studies mapping Linux auditing mechanisms, regex engine logic, and interview defense answers.

## 🚀 Active Vectors Checked
- **Signature-Based Inspection:** Parses line elements targeting specific event criteria (e.g., failed credential sequences).
- **High-Fidelity String Isolation:** Uses compiled regular expression groups to strip background telemetry text and extract pure threat IP metadata addresses.
- **Risk Aggregation Modeling:** Evaluates real-time threat volume caps per individual source address to dynamically output defensive alerts.

## 🛠️ Deployment Configuration
1. This tool uses native standard Python engines. No additional external setup libraries are required.
2. Run the detection script directly inside the target system path directory:
   ```bash
   python log_sentry.py
   ```
