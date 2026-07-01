import os
import nmap
from jinja2 import Environment, FileSystemLoader
from utils.vuln_checker import check_vulnerabilities

# Create scanner
scanner = nmap.PortScanner()

target = input("Enter target IP or CIDR range: ").strip()

print("=" * 60)
print(f"Scanning Target: {target}")
print("This may take several minutes...")
print("=" * 60)

try:
    scanner.scan(
        hosts=target,
        arguments="-Pn -sS -sV -T4"
    )

except Exception as e:
    print("Scan failed:", e)
    exit()

env = Environment(loader=FileSystemLoader("templates"))
template = env.get_template("report.html")

report_data = []

for host in scanner.all_hosts():

    print("\n" + "=" * 60)
    print("Host:", host)
    print("State:", scanner[host].state())

    host_info = {
        "ip": host,
        "hostname": scanner[host].hostname(),
        "state": scanner[host].state(),
        "os": "Unknown",
        "ports": []
    }

    # OS Detection
    if "osmatch" in scanner[host]:
        matches = scanner[host]["osmatch"]
        if matches:
            host_info["os"] = matches[0]["name"]

    print("Operating System:", host_info["os"])

    # Scan TCP/UDP protocols
    for proto in scanner[host].all_protocols():

        print("\nProtocol:", proto)

        ports = sorted(scanner[host][proto].keys())

        for port in ports:

            info = scanner[host][proto][port]

            service = info.get("name", "unknown")
            product = info.get("product", "")
            version = info.get("version", "")
            state = info.get("state", "")
            extra = info.get("extrainfo", "")

            vulnerability = check_vulnerabilities(service, port)

            print(
                f"[+] Port {port:<5} "
                f"{service:<15} "
                f"{product} {version} "
                f"({state})"
            )

            host_info["ports"].append({
                "port": port,
                "protocol": proto,
                "service": service,
                "product": product,
                "version": version,
                "state": state,
                "extra": extra,
                "vulnerability": vulnerability
            })

    report_data.append(host_info)

os.makedirs("reports", exist_ok=True)

html = template.render(data=report_data)

with open("reports/report.html", "w", encoding="utf-8") as report:
    report.write(html)

print("\n" + "=" * 60)
print("Scan Completed Successfully")
print("HTML Report saved to:")
print("reports/report.html")
print("=" * 60)

