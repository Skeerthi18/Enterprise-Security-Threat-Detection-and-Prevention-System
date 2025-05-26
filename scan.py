import yara
import os

# Load the YARA rule
rules = yara.compile(filepath='Malware_rule.yar')

# Folder to scan
folder_to_scan = '/home/kali/Desktop/adv_threat_de_pre/threat_files'

# Scan each file in the folder
for filename in os.listdir(folder_to_scan):
    filepath = os.path.join(folder_to_scan, filename)
    if os.path.isfile(filepath):
        matches = rules.match(filepath)
        if matches:
            print(f"[ALERT] Threat detected in: {filename}")
        else:
            print(f"[OK] No threat in: {filename}")

