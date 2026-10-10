 📚 Engineering Notes: OS Logging & Intrusion Detection

These notes explore the core concepts of Operating System level auditing, log aggregation, and automated incident response mechanics.

---

1. System Log Architecture (Linux syslog)
Operating systems use daemon processes (like `rsyslogd` or `systemd-journald`) to record every event that occurs on a machine. 
- **Authentication Logs (`/var/log/auth.log`):** Records all authorization metrics, track users, and captures both successful and malicious login attempts.

 2. Threat Pattern: SSH Brute-Force Attacks
An adversary attempts to gain unauthorized terminal privileges by automating thousands of guesses for passwords against a service (like SSH on Port 22). 
- **Detection Method:** This script implements **Signature-Based Threshold Analysis**. It aggregates failures by tracking specific source IP parameters over a defined volume ceiling.

 3. Regular Expressions (Regex) in Security
Security parsers use token string validation tools to extract high-fidelity properties from unstructured strings. This script uses `r'from (\d{1,3}\...)` to isolate IP addresses from text blocks, translating text lines into structural actionable metadata arrays.
