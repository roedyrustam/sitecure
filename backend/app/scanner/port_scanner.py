import asyncio
import socket
import urllib.parse
from typing import List, Dict, Any

class PortScanner:
    """
    Fast TCP Port Scanner for identifying open network services on target internal hosts.
    """
    COMMON_PORTS = {
        21: ("FTP", "HIGH", 7.5, "Service FTP terbuka tanpa enkripsi."),
        22: ("SSH", "INFO", 0.0, "Service SSH remote management terbuka."),
        23: ("Telnet", "CRITICAL", 9.0, "Service Telnet kuno terbuka (plaintext transmission)."),
        80: ("HTTP", "INFO", 0.0, "Web Server HTTP standard."),
        443: ("HTTPS", "INFO", 0.0, "Web Server HTTPS SSL/TLS."),
        1433: ("MSSQL", "HIGH", 7.3, "Database Microsoft SQL Server terbuka ke publik/network."),
        3306: ("MySQL", "HIGH", 7.3, "Database MySQL Service terbuka."),
        5432: ("PostgreSQL", "HIGH", 7.3, "Database PostgreSQL Service terbuka."),
        6379: ("Redis", "CRITICAL", 9.1, "Database In-Memory Redis terbuka (sering tanpa password)."),
        8080: ("HTTP-Alt / Admin", "LOW", 3.5, "HTTP Alternate Web App / Management Portal."),
        27017: ("MongoDB", "CRITICAL", 9.1, "Database NoSQL MongoDB Service terbuka.")
    }

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.findings = []

    async def run_scan(self, log_callback=None) -> List[Dict[str, Any]]:
        try:
            parsed = urllib.parse.urlparse(self.target_url)
            hostname = parsed.hostname or self.target_url.replace("http://", "").replace("https://", "").split("/")[0]

            if log_callback:
                await log_callback(85, f"Auditing open ports on host: {hostname}...")

            tasks = [self.check_port(hostname, port, service_info) for port, service_info in self.COMMON_PORTS.items()]
            await asyncio.gather(*tasks)

        except Exception as e:
            if log_callback:
                await log_callback(90, f"Port scan notice: {str(e)}")

        return self.findings

    async def check_port(self, host: str, port: int, service_info: tuple):
        service_name, severity, cvss, desc = service_info
        loop = asyncio.get_event_loop()
        try:
            conn = loop.create_connection(lambda: asyncio.Protocol(), host, port)
            _, writer = await asyncio.wait_for(conn, timeout=1.5)
            writer.close()
            await writer.wait_closed()

            # Port is OPEN
            if severity in ["CRITICAL", "HIGH", "MEDIUM"]:
                self.findings.append({
                    "title": f"Exposed Sensitive Service Port ({port}/{service_name})",
                    "description": f"Port {port} ({service_name}) terdeteksi TERBUKA di host target. {desc}",
                    "severity": severity,
                    "cvss_score": cvss,
                    "cwe_id": "CWE-668",
                    "affected_endpoint": f"{host}:{port}",
                    "vulnerability_type": "PORT",
                    "remediation_guide": f"Tutup port {port} dengan firewall (UFW/iptables/Security Group) atau batasi akses hanya untuk IP internal tertentu."
                })
        except Exception:
            pass
