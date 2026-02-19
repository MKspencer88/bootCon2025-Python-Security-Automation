# bootCon2025-Python-Security-Automation

This project demonstrates how I used Python to automate the detection of brute-force login attempts by analyzing authentication logs and generating alerts when suspicious activity was identified. The goal was to simulate real security monitoring workflow similar to what a SOC analyst or security engineer would build. The script ingested log data, identifed reapeated failed login attempts from the same IP, and triggered an alert when thresholds were exceeded. This project highlights my ability to automate detection logic, parse logs, and build security tooling. 

# Objectives
- Identify repeated failed login attempts from the same IP
- Detect brute-force behavior within a 1-minute window
- Automatically generate alerts and write them to a file
- Practice log parsing, regex extraction and automation

# Methodology

# 1. Log Parsing

The script reads two sources:
- The main authentication log
- A secondary alert log

It uses a regex pattern to extract:
- Timestamp
- Source IP address

# 2. Failed Login Tracking 

Failed attempts are indentified by searching for the keyword "401" in each log file. Each failed attempt is stored in a dictonary: **failed_attempts = defaultdict(list)**

# 3. Brute-Force Detection Logic

The script checks whether an IP as exceeded the threshold of 5 failed attempts within a 1 minute window.

If so, it generates an alert and writes it to alerts.txt.

# 4. Alert Output

Alers look like: 
[Alert] 192.168.1.10 had 5 failed login attempts bewteen yyyy-mm-dd hh:mm:ss and yyyy-mm-dd hh:mm:ss

# Example Code Snippet

import re
from datetime import datetime, timedelta
from collections import defaultdict
import logging
#Configurations
log_file = "authh.log"
alert_file = "alerts.txt" # <-- Alert file
fail_keyword = ["401"]
threshold = 5
window = timedelta(minutes=1)
#Regex for parsing log lines
log_line_pattern = re.compile(
   r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?'
   r'(?P<ip>\d+\.\d+\.\d+\.\d+).*',
   re.IGNORECASE
)



