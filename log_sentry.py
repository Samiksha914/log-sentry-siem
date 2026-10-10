import re
from collections import Counter

# 1. Configuration Settings
FAILED_THRESHOLD = 3  # Alert if someone fails login 3 or more times

def generate_mock_auth_log():
    """Simulates a realistic Linux security authentication log file."""
    mock_logs = [
        "Oct 10 20:00:01 server sshd[104]: Accepted password for samiksha from 192.168.1.5 port 54322 ssh2\n",
        "Oct 10 20:01:15 server sshd[105]: Failed password for root from 203.0.113.42 port 49152 ssh2\n",
        "Oct 10 20:01:20 server sshd[106]: Failed password for root from 203.0.113.42 port 49153 ssh2\n",
        "Oct 10 20:01:25 server sshd[107]: Failed password for root from 203.0.113.42 port 49154 ssh2\n",
        "Oct 10 20:02:40 server sshd[108]: Failed password for admin from 198.51.100.12 port 38221 ssh2\n",
        "Oct 10 20:03:10 server sshd[109]: Accepted password for samiksha from 192.168.1.5 port 54328 ssh2\n"
    ]
    with open("auth.log", "w") as log_file:
        log_file.writelines(mock_logs)
    print("📋 Mock Linux authentication log ('auth.log') generated successfully.")

def parse_security_logs(log_filename):
    """Parses the log file to trace anomalies and threat vectors."""
    failed_attempts = []
    
    print("\n🔍 Scanning log entries for indicators of compromise...")
    
    with open(log_filename, "r") as file:
        for line in file:
            # Look for lines containing "Failed password"
            if "Failed password" in line:
                # Use regular expressions to cleanly extract the attacker's IP address
                ip_match = re.search(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    failed_attempts.append(ip_match.group(1))
    
    # 2. Risk Aggregation (Count failures per IP)
    ip_counts = Counter(failed_attempts)
    
    # 3. Alert Generation Logic
    threats_found = False
    for ip, count in ip_counts.items():
        if count >= FAILED_THRESHOLD:
            print(f"\n🚨 [CRITICAL ALERT] Potential SSH Brute-Force Attack Detected!")
            print(f"👉 Malicious Vector IP: {ip} | Failed Attempts: {count}")
            threats_found = True
            
    if not threats_found:
        print("✅ Scan complete. No anomalous brute-force signatures detected.")

if __name__ == "__main__":
    # Step A: Setup the fake system log environment
    generate_mock_auth_log()
    
    # Step B: Run the defensive analytics engine
    parse_security_logs("auth.log")
