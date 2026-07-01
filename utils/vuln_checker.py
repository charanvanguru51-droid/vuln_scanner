# utils/vuln_checker.py

def check_vulnerabilities(service, port):
    """
    Simple vulnerability checker based on common insecure services and ports.
    """

    service = service.lower()

    vulnerabilities = []

    # Insecure services
    if service == "ftp":
        vulnerabilities.append("FTP is insecure. Use SFTP/FTPS.")

    if service == "telnet":
        vulnerabilities.append("Telnet transmits data in plaintext.")

    if service == "http":
        vulnerabilities.append("HTTP is not encrypted. Consider HTTPS.")

    if service == "smtp":
        vulnerabilities.append("Check SMTP for open relay configuration.")

    if service == "mysql":
        vulnerabilities.append("Restrict MySQL access to trusted hosts.")

    if service == "microsoft-ds":
        vulnerabilities.append("SMB service detected. Ensure SMBv1 is disabled.")

    if service == "rdp":
        vulnerabilities.append("Enable MFA and restrict RDP access.")

    # Common risky ports
    if port == 21:
        vulnerabilities.append("FTP Port (21) is open.")

    if port == 23:
        vulnerabilities.append("Telnet Port (23) is open.")

    if port == 25:
        vulnerabilities.append("SMTP Port (25) is open.")

    if port == 53:
        vulnerabilities.append("DNS Port (53) is open. Verify DNS configuration.")

    if port == 80:
        vulnerabilities.append("HTTP Port (80) is open.")

    if port == 110:
        vulnerabilities.append("POP3 is insecure without TLS.")

    if port == 135:
        vulnerabilities.append("Windows RPC exposed.")

    if port == 139:
        vulnerabilities.append("NetBIOS service exposed.")

    if port == 143:
        vulnerabilities.append("IMAP detected. Use SSL/TLS.")

    if port == 443:
        vulnerabilities.append("HTTPS detected. Verify TLS configuration.")

    if port == 445:
        vulnerabilities.append("SMB Port (445) exposed. Possible ransomware target.")

    if port == 1433:
        vulnerabilities.append("Microsoft SQL Server exposed.")

    if port == 1521:
        vulnerabilities.append("Oracle Database listener exposed.")

    if port == 3306:
        vulnerabilities.append("MySQL service exposed.")

    if port == 3389:
        vulnerabilities.append("Remote Desktop (RDP) exposed.")

    if port == 5432:
        vulnerabilities.append("PostgreSQL service exposed.")

    if port == 5900:
        vulnerabilities.append("VNC service exposed.")

    if port == 6379:
        vulnerabilities.append("Redis service exposed. Disable public access.")

    if port == 8080:
        vulnerabilities.append("Alternative HTTP service exposed.")

    if not vulnerabilities:
        return "No obvious issues detected."

    return " | ".join(vulnerabilities)
