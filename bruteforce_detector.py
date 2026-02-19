import re
from datetime import datetime, timedelta
from collections import defaultdict
import logging
# Configurations
log_file = "authh.log"
alert_file = "alerts.txt" # <-- Alert file
fail_keyword = ["401"]
threshold = 5
window = timedelta(minutes=1)
# Regex for parsing log lines
log_line_pattern = re.compile(
   r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?'
   r'(?P<ip>\d+\.\d+\.\d+\.\d+).*',
   re.IGNORECASE
)
# Data structure to store failure
failed_attempts = defaultdict(list)

with open(alert_file, 'r') as f:
   for line in f:
      if any(keyword in line.lower() for keyword in fail_keyword):
          match = log_line_pattern.match(line)
          if match:
             timestamp = datetime.strptime(match.group('timestamp'), "%Y-%m-%d >
             ip = match.group('ip')
             failed_attempts[ip].append(timestamp)

# Read log file and collect failed attempts
with open(log_file, 'r') as log:
        for line in log:
            if any(keyword in line.lower() for keyword in fail_keyword):
                match = log_line_pattern.match(line)
                if match:
                    timestamps = datetime.strptime(match.group('timestamp'), "%>
                    ip = match.group('ip')
                    failed_attempts[ip].append(timestamps)
with open("alerts.txt", "w") as alert_out:
    for ip, timestamps in failed_attempts.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            j = i + threshold
            if j <= len(timestamps):
if timestamps[j - 1] - timestamps[i] <= window:
                   count = j - i
                   alert_msg = (
                       f"[Alert] {ip} had {count} failed logins between "
                       f"{timestamps[i]} and {timestamps[j-1]}"
                   )
                   print (alert_msg)
                   alert_out.write(alert_msg + "\n")

# Analyze for brute-force patterns
for ip, timestamps in failed_attempts.items():
    timestamps.sort()
    for i in range(len(timestamps)):
        window_start = timestamps[i]
        count = 1
        for j in range(i + 1, len(timestamps)):
            if timestamps[j] - window_start <= window:
                count += 1
else:
               break
        if count >= threshold:
            print (f"[ALERT!]{ip} had {count} failed logins between {timestamps>
            break

# Compose alert message
            print (alert_msg)
            alert_out.write(alert_msg + "\n") # <-- Write to file
            break #Alert triggered, no need to check further for this IP
