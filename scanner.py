import nmap
from jinja2 import Environment, FileSystemLoader
from utils.vuln_checker import check_vulnerabilities
scanner = nmap.PortScanner()
target = input("Enter target IP or range: ")
print("🔍 Scanning...")
scanner.scan(hosts=target, arguments='-sS -sV')
env = Environment(loader=FileSystemLoader('templates'))
template = env.get_template('report.html')
data = []
for host in scanner.all_hosts():
    host_data = {"ip": host, "ports": []}
    for proto in scanner[host].all_protocols():
        for port in scanner[host][proto].keys():
            service = scanner[host][proto][port]['name']
            vuln = check_vulnerabilities(service, port)
            host_data["ports"].append({
                "port": port,
                "service": service,
                "vulnerability": vuln
            })
    data.append(host_data)
output = template.render(data=data)
with open("reports/report.html", "w") as f:
    f.write(output)
print("✅ Report generated: reports/report.html")
