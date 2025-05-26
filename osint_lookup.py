import json
import requests

API_KEY = "30E5tQllYQAA34Ra5mrYGyituKsXeqtU"  # replace this with your own

with open("../parsed/parsed_cowrie.json", "r") as f:
    data = json.load(f)

ips = list(set(entry['src_ip'] for entry in data if entry['src_ip']))

osint_results = {}

for ip in ips:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        osint_results[ip] = response.json()
    else:
        osint_results[ip] = {"error": "Failed to fetch"}

# Save to file
with open("../osint_results/vt_ip_results.json", "w") as f:
    json.dump(osint_results, f, indent=4)

print(f"[+] OSINT results saved to osint_results/vt_ip_results.json")
