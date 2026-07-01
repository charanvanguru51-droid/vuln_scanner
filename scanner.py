import os
import nmap
from jinja2 import Environment, FileSystemLoader
from utils.vuln_checker import check_vulnerabilities

# -------------------------------
# Initialize Nmap Scanner
# -------------------------------
scanner = nmap.PortScanner()

# -------------------------------
# Target Input
# -------------------------------
target = input("Enter target IP / Hostname / CIDR: ").strip()

print("=" * 60)
print("        PYTHON VULNERABILITY SCANNER")
print("=" * 60)
print(f"Target : {target}")
print("Scanning all TCP ports...")
print("Please wait...\n")

# -------------------------------
# Start Scan
# -------------------------------
try:
    scanner.scan(
        hosts=target,
        arguments="-Pn -sS -sV -O -sC -T4 -p-"
    )
except Exception as e:
    print("Scan failed!")
    print(e)
    exit()

# -------------------------------
# Load HTML Template
# -------------------------------
env = Environment(loader=FileSystemLoader("templates"))
template = env.get_template("report.html")

report = []

# -------------------------------
# Process Results
# -------------------------------
for host in scanner.all_hosts():

    print("=" * 60)
    print("Host :", host)
    print("State:", scanner[host].state())

    hostname = scanner[host].hostname()

    # ---------------------------
    # OS Detection
    # ---------------------------
    os_name = "Unknown"

    if "osmatch" in scanner[host]:
        matches = scanner[host]["osmatch"]
        if len(matches) > 0:
            os_name = matches[0]["name"]

    print("Hostname :", hostname)
    print("OS       :", os_name)

    host_data = {
        "ip": host,
        "hostname": hostname,
        "state": scanner[host].state(),
        "os": os_name,
        "ports": []
    }

    # ---------------------------
    # Protocols
    # ---------------------------
    for proto in scanner[host].all_protocols():

        print(f"\nProtocol : {proto}")

        ports = sorted(scanner[host][proto].keys())

        for port in ports:

            info = scanner[host][proto][port]

            state = info.get("state", "")
            service = info.get("name", "")
            product = info.get("product", "")
            version = info.get("version", "")
            extra = info.get("extrainfo", "")

            vulnerability = check_vulnerabilities(
                service,
                port
            )

            print(
                f"[+] {port:<6}"
                f"{service:<18}"
                f"{product:<20}"
                f"{version:<15}"
                f"{state}"
            )

            host_data["ports"].append({
                "port": port,
                "protocol": proto,
                "service": service,
                "product": product,
                "version": version,
                "state": state,
                "extra": extra,
                "vulnerability": vulnerability
            })

    report.append(host_data)

# -------------------------------
# Create Reports Folder
# -------------------------------
os.makedirs("reports", exist_ok=True)

# -------------------------------
# Generate HTML Report
# -------------------------------
html = template.render(data=report)

with open(
    "reports/report.html",
    "w",
    encoding="utf-8"
) as file:
    file.write(html)

# -------------------------------
# Save JSON Report (Optional)
# -------------------------------
import json

with open(
    "reports/report.json",
    "w",
    encoding="utf-8"
) as file:
    json.dump(report, file, indent=4)

# -------------------------------
# Summary
# -------------------------------
print("\n")
print("=" * 60)
print("SCAN COMPLETED")
print("=" * 60)

for host in report:

    print(f"\nHost : {host['ip']}")

    open_ports = len(host["ports"])

    print("Open Ports :", open_ports)

print("\nReports Generated Successfully")

print("HTML Report : reports/report.html")
print("JSON Report : reports/report.json")

print("=" * 60)
