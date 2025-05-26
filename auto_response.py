import json
import subprocess
import requests
import time

VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
LOG_FILE = "../parsed/parsed_cowrie.json"
BLOCKLIST_FILE = "../logs/blocked_ips.txt"
THRESHOLD = 10  # failed attempts before action

def get_ip_counts(log_file):
    with open(log_file) as f:
        data = json.load(f)
    
    ip_counts = {}
    for entry in data:
        if entry["event"] == "cowrie.login.failed":
            ip = entry["src_ip"]
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    return ip_counts

def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        res = r.json()
        try:
            score = res["data"]["attributes"]["last_analysis_stats"]["malicious"]
            return score
        except:
            return 0
    return 0

def block_ip(ip):
    subprocess.call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    with open(BLOCKLIST_FILE, "a") as f:
        f.write(f"{ip}\n")
    print(f"[+] Blocked IP: {ip}")

def already_blocked(ip):
    try:
        with open(BLOCKLIST_FILE, "r") as f:
            return ip in f.read()
    except FileNotFoundError:
        return False

def main():
    print("[*] Running SOAR automation...")
    ip_counts = get_ip_counts(LOG_FILE)
    for ip, count in ip_counts.items():
        if count >= THRESHOLD and not already_blocked(ip):
            print(f"[!] Detected brute-force from {ip} ({count} attempts)")
            vt_score = check_ip_virustotal(ip)
            if vt_score >= 1:
                print(f"[!] VirusTotal score {vt_score}, blocking IP {ip}")
                block_ip(ip)
            else:
                print(f"[~] VirusTotal score {vt_score}, skipping block")
    print("[*] Automation complete.")

if __name__ == "__main__":
    main()
