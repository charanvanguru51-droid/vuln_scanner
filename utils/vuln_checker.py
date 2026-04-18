def check_vulnerabilities(service, port):
    if service == "ftp":
        return "⚠️ FTP is insecure (use SFTP)"
    elif service == "telnet":
        return "⚠️ Telnet is insecure"
    elif port == 80:
        return "⚠️ HTTP detected (use HTTPS)"
    elif port == 445:
        return "⚠️ SMB port open (possible risk)"
    else:
        return "Safe"
