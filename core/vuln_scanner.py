"""Evidence-based network exposure scanner.

The scanner checks TCP reachability on local or private targets. It does not
attempt exploitation and it does not claim a CVE without product/version
evidence.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

from .logger import get_logger
from .threat_intel import ThreatIntelligence

logger = get_logger(__name__)


class VulnerabilityScanner:
    """Scan private hosts for exposed TCP services and hardening risks."""

    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 6379,
        8080, 8443, 9200, 27017,
    ]

    EXPOSURE_RULES = {
        21: ("MEDIUM", "FTP service exposed", "Prefer SFTP and restrict source addresses."),
        23: ("CRITICAL", "Telnet service exposed", "Disable Telnet and use SSH with strong authentication."),
        135: ("MEDIUM", "Windows RPC exposed", "Limit RPC access to trusted management networks."),
        139: ("HIGH", "NetBIOS file sharing exposed", "Disable legacy NetBIOS where possible and restrict it at the firewall."),
        445: ("HIGH", "SMB service exposed", "Block SMB from untrusted networks and disable SMBv1."),
        1433: ("HIGH", "Microsoft SQL Server exposed", "Restrict database access to application and administration hosts."),
        3306: ("HIGH", "MySQL exposed", "Bind the database privately and restrict inbound firewall rules."),
        3389: ("HIGH", "Remote Desktop exposed", "Require NLA and restrict RDP through VPN or a trusted allowlist."),
        5432: ("HIGH", "PostgreSQL exposed", "Bind the database privately and restrict inbound firewall rules."),
        5900: ("HIGH", "VNC remote control exposed", "Restrict VNC to a management network and require encrypted transport."),
        5985: ("MEDIUM", "Unencrypted WinRM listener exposed", "Prefer WinRM over HTTPS and restrict management sources."),
        6379: ("CRITICAL", "Redis exposed", "Bind Redis privately, require authentication, and block public access."),
        9200: ("HIGH", "Elasticsearch exposed", "Require authentication and restrict access to trusted application hosts."),
        27017: ("HIGH", "MongoDB exposed", "Require authentication and restrict access to trusted application hosts."),
    }

    def __init__(
        self,
        timeout: float = 0.75,
        max_hosts: int = 256,
        max_ports: int = 65535,
        workers: int = 64,
        allow_public: bool = False,
    ) -> None:
        self.timeout = max(0.05, float(timeout))
        self.max_hosts = max_hosts
        self.max_ports = max_ports
        self.workers = max(1, min(workers, 256))
        self.allow_public = allow_public
        self.threat_intel = ThreatIntelligence()

    def scan(
        self,
        target: str,
        quick: bool = False,
        port_range: str | None = None,
        aggressive: bool = False,
    ) -> Dict[str, Any]:
        """Scan a target host or CIDR and return observed exposures."""
        del aggressive  # Retained for CLI compatibility; exploitation is never performed.
        hosts = self._expand_targets(target)
        ports = self.COMMON_PORTS if quick else self._parse_ports(port_range or "1-1024")
        started = datetime.now(timezone.utc)
        host_results: List[Dict[str, Any]] = []
        open_ports: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        logger.info("Scanning %s host(s) across %s TCP port(s)", len(hosts), len(ports))
        for host in hosts:
            discovered = self._scan_host(host, ports)
            host_rows = []
            for port in discovered:
                port_info = self.threat_intel.get_port_info(port)
                rule = self.EXPOSURE_RULES.get(port)
                risk = rule[0] if rule else ("MEDIUM" if port in (80, 443, 8080, 8443) else "LOW")
                row = {
                    "host": host,
                    "port": port,
                    "service": port_info["service"],
                    "risk_level": risk,
                }
                host_rows.append(row)
                open_ports.append(row)
                if rule:
                    severity, title, remediation = rule
                    findings.append({
                        "id": f"network-{host.replace(':', '_')}-{port}",
                        "category": "network exposure",
                        "severity": severity,
                        "title": title,
                        "description": f"TCP {port} is reachable on {host}. This is an exposure finding, not proof of a CVE.",
                        "evidence": f"TCP connection to {host}:{port} succeeded.",
                        "remediation": remediation,
                        "host": host,
                        "port": port,
                        "service": port_info["service"],
                        "cve": None,
                    })
            host_results.append({"host": host, "open_ports": host_rows})

        finished = datetime.now(timezone.utc)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            key = finding["severity"].lower()
            severity_counts[key] += 1
        summary = {
            **severity_counts,
            "pass": 0,
            "error": 0,
            "info": 0,
            "total": len(findings),
            "actionable": len(findings),
            "patchable": 0,
        }
        score = max(0, 100 - severity_counts["critical"] * 25 - severity_counts["high"] * 15 - severity_counts["medium"] * 7 - severity_counts["low"] * 2)
        return {
            "scan_type": "network_exposure",
            "timestamp": started.isoformat(),
            "completed_at": finished.isoformat(),
            "duration_seconds": round((finished - started).total_seconds(), 3),
            "target": target,
            "scope": "public targets allowed" if self.allow_public else "private and loopback targets only",
            "status": "completed",
            "score": score,
            "summary": summary,
            "scanned_hosts": len(hosts),
            "scanned_ports_per_host": len(ports),
            "hosts": host_results,
            "open_ports": open_ports,
            "findings": findings,
            "vulnerabilities": findings,
            "total_vulns": len(findings),
            "limitations": [
                "Open ports are exposures, not confirmed product vulnerabilities.",
                "CVE assignment requires authenticated inventory or reliable product/version evidence.",
            ],
        }

    def _scan_host(self, host: str, ports: Iterable[int]) -> List[int]:
        open_ports: List[int] = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(self._is_port_open, host, port): port for port in ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except OSError:
                    continue
        return sorted(open_ports)

    def _is_port_open(self, target: str, port: int) -> bool:
        try:
            with socket.create_connection((target, port), timeout=self.timeout):
                return True
        except (socket.timeout, OSError):
            return False

    def _expand_targets(self, target: str) -> List[str]:
        value = target.strip()
        if not value or any(char.isspace() for char in value):
            raise ValueError("Target must be one hostname, IP address, or CIDR range.")

        if "/" in value:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR target: {value}") from exc
            if network.num_addresses > self.max_hosts:
                raise ValueError(f"CIDR target exceeds the {self.max_hosts}-address safety limit.")
            addresses = [str(address) for address in network.hosts()]
            if network.num_addresses == 1:
                addresses = [str(network.network_address)]
            self._require_private(addresses)
            return addresses

        try:
            literal = ipaddress.ip_address(value)
            addresses = [str(literal)]
        except ValueError:
            try:
                resolved = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
            except socket.gaierror as exc:
                raise ValueError(f"Could not resolve target: {value}") from exc
            addresses = sorted({item[4][0] for item in resolved})
            if not addresses:
                raise ValueError(f"Could not resolve target: {value}")

        self._require_private(addresses)
        return [value]

    def _require_private(self, addresses: Iterable[str]) -> None:
        if self.allow_public:
            return
        for value in addresses:
            address = ipaddress.ip_address(value)
            if not (address.is_private or address.is_loopback or address.is_link_local):
                raise ValueError(
                    "Public targets are disabled by default. Scan only systems you own on a private network."
                )

    def _parse_ports(self, expression: str) -> List[int]:
        ports = set()
        try:
            for segment in expression.split(","):
                item = segment.strip()
                if not item:
                    raise ValueError
                if "-" in item:
                    start_text, end_text = item.split("-", 1)
                    start, end = int(start_text), int(end_text)
                    if start > end:
                        raise ValueError
                    ports.update(range(start, end + 1))
                else:
                    ports.add(int(item))
        except ValueError as exc:
            raise ValueError("Ports must look like 443, 80,443, or 1-1024.") from exc

        if not ports or min(ports) < 1 or max(ports) > 65535:
            raise ValueError("Ports must be between 1 and 65535.")
        if len(ports) > self.max_ports:
            raise ValueError(f"Port selection exceeds the {self.max_ports}-port safety limit.")
        return sorted(ports)
