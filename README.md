# 🔍 Python Vulnerability Scanner

A Python-based Vulnerability Scanner that uses **Nmap** to scan hosts, detect open ports, identify running services, and generate an HTML report with basic vulnerability analysis.

---

## 📌 Features

- Scan single IP, hostname, or network range
- Detect open TCP ports
- Service and version detection
- OS detection
- Default Nmap NSE script scanning
- HTML report generation
- JSON report generation
- Basic vulnerability detection
- Clean and easy-to-read output

---

## 📂 Project Structure

```
vuln_scanner/
│
├── scanner.py
├── requirements.txt
├── README.md
│
├── reports/
│   ├── report.html
│   └── report.json
│
├── templates/
│   └── report.html
│
└── utils/
    ├── __init__.py
    └── vuln_checker.py
```

---

## 🛠 Requirements

- Python 3.10+
- Nmap
- python-nmap
- Jinja2

---

## 📥 Installation

### Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/vuln_scanner.git
cd vuln_scanner
```

### Create Virtual Environment

Linux

```bash
python3 -m venv venv
```

Activate

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Install Nmap

Ubuntu/Kali

```bash
sudo apt update
sudo apt install nmap
```

Verify installation

```bash
nmap --version
```

---

## ▶ Running the Scanner

```bash
sudo python3 scanner.py
```

Example

```
Enter target IP / Hostname / CIDR:

192.168.1.10
```

or

```
scanme.nmap.org
```

---

## Scan Options Used

```
-Pn
-sS
-sV
-sC
-O
-T4
-p-
```

### Explanation

| Option | Description |
|---------|-------------|
| -Pn | Skip host discovery |
| -sS | TCP SYN Scan |
| -sV | Service Version Detection |
| -sC | Default NSE Scripts |
| -O | OS Detection |
| -T4 | Faster Scan |
| -p- | Scan all TCP ports |

---

## Generated Reports

After the scan finishes:

```
reports/
```

contains

```
report.html
report.json
```

Open HTML report:

```bash
xdg-open reports/report.html
```

---

## Example Output

| Port | Service | Vulnerability |
|------|----------|---------------|
|22|SSH|No obvious issues detected|
|80|HTTP|HTTP detected. Use HTTPS|
|445|SMB|SMB service detected|

---

## Vulnerability Checks

The scanner identifies common insecure services such as

- FTP
- Telnet
- HTTP
- SMB
- NetBIOS
- RDP
- MySQL
- PostgreSQL
- Redis
- Oracle Database
- Microsoft SQL Server

---

## Technologies Used

- Python
- Nmap
- python-nmap
- Jinja2
- HTML
- CSS

---

## Future Improvements

- CVE Detection
- CVSS Score
- PDF Report
- Email Notifications
- Dashboard
- Banner Grabbing
- Multi-threaded Scanning
- Database Support
- Scheduled Scans

---

## Disclaimer

This tool is intended **only for educational purposes and authorized security testing**.

Only scan systems that you own or have explicit permission to assess.

Unauthorized scanning may violate laws or organizational policies.

---

## Author

**Charan Kumar**

B.Tech CSE (Cyber Security)

VIT-AP University

GitHub: https://github.com/charanvanguru51-droid
