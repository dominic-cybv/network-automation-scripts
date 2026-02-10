# Network Automation & Security Auditing Scripts

This repository contains a collection of Python scripts developed for network reconnaissance, log analysis, and system integrity monitoring. These tools demonstrate core cybersecurity automation workflows utilizing the `socket`, `re` (Regex), and `hashlib` libraries.

## Files Included

### 1. `network_scanner.py` (Network Reconnaissance)
A custom port scanning tool that identifies open ports and retrieves service banners from target hosts.
* **Key Features:** Socket-based connection handling, service fingerprinting, and error management for non-responsive hosts.
* **Usage:** Used for initial vulnerability assessment and mapping attack surfaces.

### 2. `log_analyzer.py` (Threat Detection)
An automated log parsing script designed to detect brute-force attack patterns in server authentication logs.
* **Key Features:** Regex pattern matching for SSH failure logs, IP tracking, and threshold-based alerting.
* **Usage:** Automates Blue Team monitoring tasks to identify potential intrusions.

### 3. `file_integrity_checker.py` (NIST Compliance)
A file integrity monitoring (FIM) tool that generates SHA-256 hashes of critical system files to detect unauthorized modifications.
* **Key Features:** Cryptographic hashing, baseline comparison, and tampering alerts.
* **Usage:** Ensures compliance with NIST controls regarding System Integrity and Configuration Management.

---
*Disclaimer: These scripts are for educational and defensive purposes only. Developed as part of the Cyber Operations curriculum at the University of Arizona.*
