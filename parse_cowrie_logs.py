import json
import os

log_file = "/home/kali/cowrie/var/log/cowrie/cowrie.log"
output_file = "../parsed/parsed_cowrie.json"

parsed_entries = []

with open(log_file, "r") as f:
    for line in f:
        try:
            log_entry = json.loads(line)
            # Extract fields
            timestamp = log_entry.get("timestamp")
            src_ip = log_entry.get("src_ip")
            eventid = log_entry.get("eventid")
            username = log_entry.get("username")
            password = log_entry.get("password")

            parsed_entries.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "event": eventid,
                "username": username,
                "password": password
            })
        except json.JSONDecodeError:
            continue

# Save parsed data
os.makedirs("../parsed", exist_ok=True)
with open(output_file, "w") as out:
    json.dump(parsed_entries, out, indent=4)

print(f"[+] Parsed {len(parsed_entries)} log entries to {output_file}")
