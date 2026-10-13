"""Defensive vulnerability intelligence from local, NVD, and CISA sources."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# Writeups are defensive: drop references that point at exploit code or proofs of concept.
EXPLOIT_HOSTS = ("packetstormsecurity.", "exploit-db.com", "rapid7.com/db/modules", "0day.today")


def _severity(cvss: float | int | None) -> str:
    if cvss is None:
        return "UNKNOWN"
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    return "LOW"


class ThreatIntelligence:
    """Look up CVE context without including exploit code or payloads."""

    PORT_MAP = {
        21: {"service": "ftp", "technique": "T1021.002", "label": "File Transfer Protocols"},
        22: {"service": "ssh", "technique": "T1021.004", "label": "SSH"},
        23: {"service": "telnet", "technique": "T1021.002", "label": "Remote Services"},
        25: {"service": "smtp", "technique": "T1071.003", "label": "Mail Protocols"},
        53: {"service": "dns", "technique": "T1071.004", "label": "DNS"},
        80: {"service": "http", "technique": "T1190", "label": "Public-Facing Application"},
        110: {"service": "pop3", "technique": "T1071.003", "label": "Mail Protocols"},
        111: {"service": "rpcbind", "technique": "T1021", "label": "Remote Services"},
        135: {"service": "msrpc", "technique": "T1021.002", "label": "Windows RPC"},
        139: {"service": "netbios-ssn", "technique": "T1021.002", "label": "NetBIOS"},
        143: {"service": "imap", "technique": "T1071.003", "label": "Mail Protocols"},
        443: {"service": "https", "technique": "T1190", "label": "Public-Facing Application"},
        445: {"service": "microsoft-ds", "technique": "T1021.002", "label": "SMB"},
        993: {"service": "imaps", "technique": "T1071.003", "label": "Mail Protocols"},
        995: {"service": "pop3s", "technique": "T1071.003", "label": "Mail Protocols"},
        1433: {"service": "mssql", "technique": "T1505", "label": "Database"},
        3306: {"service": "mysql", "technique": "T1505", "label": "Database"},
        3389: {"service": "rdp", "technique": "T1021.001", "label": "Remote Desktop Protocol"},
        5432: {"service": "postgresql", "technique": "T1505", "label": "Database"},
        5900: {"service": "vnc", "technique": "T1021.005", "label": "VNC"},
        5985: {"service": "winrm-http", "technique": "T1021.006", "label": "Windows Remote Management"},
        5986: {"service": "winrm-https", "technique": "T1021.006", "label": "Windows Remote Management"},
        6379: {"service": "redis", "technique": "T1505", "label": "Database"},
        8080: {"service": "http-alt", "technique": "T1190", "label": "Public-Facing Application"},
        8443: {"service": "https-alt", "technique": "T1190", "label": "Public-Facing Application"},
        9200: {"service": "elasticsearch", "technique": "T1505", "label": "Database"},
        27017: {"service": "mongodb", "technique": "T1505", "label": "Database"},
    }

    LOCAL_CVES: Dict[str, Dict[str, Any]] = {
        "CVE-2021-41773": {
            "title": "Apache HTTP Server path traversal",
            "cvss": 9.8,
            "description": "Path traversal in Apache HTTP Server 2.4.49; incomplete remediation also affected 2.4.50.",
            "plain": "A narrowly affected Apache version can expose files outside the web root and, in some configurations, permit command execution.",
            "business_risk": "An exposed server may leak configuration, credentials, or application source.",
            "affected": "Apache HTTP Server 2.4.49 and the related incomplete fix in 2.4.50.",
            "detection": ["Inventory Apache versions.", "Review access logs for encoded path traversal attempts."],
            "mitigation": ["Upgrade Apache HTTP Server to a currently supported release.", "Rotate secrets exposed to the web-service account."],
            "known_exploited": True,
            "cwe": ["CWE-22"],
        },
        "CVE-2021-44228": {
            "title": "Apache Log4j2 JNDI injection (Log4Shell)",
            "cvss": 10.0,
            "description": "JNDI injection in vulnerable Log4j 2 releases can permit remote code execution when attacker-controlled input is logged.",
            "plain": "A vulnerable Java application can execute attacker-controlled code after logging crafted input.",
            "business_risk": "Internet-facing Java applications and vendor appliances require complete dependency inventory, not only filename searches.",
            "affected": "Product and Java-version-specific ranges; confirm with Apache and vendor advisories.",
            "detection": ["Use an SBOM or dependency inventory to find Log4j core.", "Review application and egress logs for unexpected JNDI lookups."],
            "mitigation": ["Upgrade to the vendor-supported fixed Log4j release.", "Isolate and investigate systems that show exploitation indicators."],
            "known_exploited": True,
            "cwe": ["CWE-917"],
        },
        "CVE-2017-0144": {
            "title": "Windows SMB remote code execution (MS17-010)",
            "cvss": 8.1,
            "description": "A flaw in SMBv1 on unpatched Windows can permit remote code execution.",
            "plain": "An unpatched Windows machine using SMBv1 can be taken over from the network without a password.",
            "business_risk": "This class of flaw enabled destructive worm and ransomware outbreaks.",
            "affected": "Unsupported or unpatched Microsoft Windows systems using SMBv1.",
            "detection": ["Confirm MS17-010 updates are installed.", "Verify SMBv1 is disabled and TCP 445 is not internet exposed."],
            "mitigation": ["Install all supported Windows security updates.", "Disable SMBv1 and restrict TCP 445 to trusted networks."],
            "known_exploited": True,
            "cwe": ["CWE-119"],
        },
        "CVE-2022-30190": {
            "title": "Microsoft Windows Support Diagnostic Tool code execution (Follina)",
            "cvss": 7.8,
            "description": "A crafted document can invoke MSDT and execute code with the calling application's privileges.",
            "plain": "A malicious Office document can abuse a Windows troubleshooting component to run commands.",
            "business_risk": "Email-delivered documents can lead to workstation compromise even when macros are disabled.",
            "affected": "Windows and Office combinations listed in Microsoft's security guidance.",
            "detection": ["Review process telemetry for Office spawning msdt.exe.", "Confirm the relevant Windows security updates are installed."],
            "mitigation": ["Apply current Microsoft security updates.", "Investigate Office-to-MSDT process chains as a possible incident."],
            "known_exploited": True,
            "cwe": ["CWE-610"],
        },
        "CVE-2023-23397": {
            "title": "Microsoft Outlook elevation of privilege",
            "cvss": 9.8,
            "description": "A specially crafted Outlook item can trigger outbound NTLM authentication before the message is opened.",
            "plain": "Receiving a malicious calendar or mail item may expose a reusable Windows authentication response.",
            "business_risk": "Credential material can be relayed or cracked, creating a path into Windows accounts and internal services.",
            "affected": "Affected Microsoft Outlook for Windows releases; confirm exact builds with Microsoft guidance.",
            "detection": ["Run Microsoft's published Exchange/Outlook investigation tooling.", "Review outbound SMB traffic and suspicious reminder properties."],
            "mitigation": ["Apply current Microsoft Office security updates.", "Block outbound SMB and require protections against NTLM relay."],
            "known_exploited": True,
            "cwe": ["CWE-200"],
        },
    }

    def __init__(self, cache_dir: str | Path | None = None, timeout: int = 20) -> None:
        self.cve_database = dict(self.LOCAL_CVES)
        self.timeout = timeout
        self.cache_dir = Path(cache_dir) if cache_dir else Path(__file__).resolve().parent.parent / "data"
        self.kev_path = self.cache_dir / "cisa_kev.json"
        self._kev_payload = self._load_kev_cache()

    def list_cves(self, limit: int | None = None) -> List[Dict[str, Any]]:
        rows = []
        for cve_id, info in self.cve_database.items():
            rows.append(self._summary(cve_id, info, "local"))
        for item in self._kev_items():
            cve_id = item.get("cveID", "")
            if cve_id and cve_id not in self.cve_database:
                rows.append(self._kev_to_info(item, summary_only=True))
        rows.sort(key=lambda row: (row.get("date_added") or "", row["cve"]), reverse=True)
        return rows[:limit] if limit else rows

    def search(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        needle = query.strip().lower()
        if not needle:
            return self.list_cves(limit=limit)
        matches = []
        for row in self.list_cves():
            haystack = " ".join(str(value) for value in row.values()).lower()
            if needle in haystack:
                matches.append(row)
                if len(matches) >= limit:
                    break
        return matches

    def get_port_info(self, port: int) -> Dict[str, Any]:
        info = self.PORT_MAP.get(int(port))
        if not info:
            return {"port": int(port), "service": "unknown", "technique": None, "label": "No local mapping"}
        return {"port": int(port), **info}

    def get_cve_info(self, cve_id: str, live: bool = False) -> Dict[str, Any]:
        key = self._validate_cve(cve_id)
        local = self.cve_database.get(key)
        kev_item = next((item for item in self._kev_items() if item.get("cveID") == key), None)
        if live:
            try:
                nvd = self.fetch_nvd_cve(key)
                if local:
                    nvd.update({name: value for name, value in local.items() if name not in nvd or not nvd[name] or name == "title"})
                if kev_item:
                    nvd.update(self._kev_fields(kev_item))
                    if nvd.get("title") == key and kev_item.get("vulnerabilityName"):
                        nvd["title"] = kev_item["vulnerabilityName"]
                return nvd
            except (OSError, ValueError, urllib.error.URLError) as exc:
                fallback = self._offline_cve(key, local, kev_item)
                fallback["live_error"] = str(exc)
                return fallback
        return self._offline_cve(key, local, kev_item)

    def fetch_nvd_cve(self, cve_id: str) -> Dict[str, Any]:
        key = self._validate_cve(cve_id)
        url = NVD_CVE_API + "?" + urllib.parse.urlencode({"cveId": key})
        headers = {"Accept": "application/json", "User-Agent": "SecuritySuite/2.0 defensive-scanner"}
        api_key = os.environ.get("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            payload = json.load(response)
        rows = payload.get("vulnerabilities") or []
        if not rows:
            return {"cve": key, "found": False, "source": "NVD", "note": "NVD returned no record."}
        cve = rows[0].get("cve", {})
        score, severity, vector = self._extract_cvss(cve.get("metrics", {}))
        descriptions = cve.get("descriptions", [])
        description = next((row.get("value") for row in descriptions if row.get("lang") == "en"), "")
        weaknesses = []
        for weakness in cve.get("weaknesses", []):
            weaknesses.extend(row.get("value") for row in weakness.get("description", []) if row.get("lang") == "en")
        references = [
            row["url"] for row in cve.get("references", [])
            if row.get("url") and not self._is_exploit_reference(row)
        ][:20]
        info = {
            "cve": key,
            "found": True,
            "title": key,
            "description": description,
            "plain": description,
            "cvss": score,
            "severity": severity,
            "vector": vector,
            "cwe": list(dict.fromkeys(weaknesses)),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "vuln_status": cve.get("vulnStatus"),
            "references": references,
            "source": "NIST NVD live API",
            "known_exploited": bool(cve.get("cisaExploitAdd")),
        }
        if cve.get("cisaExploitAdd"):
            info.update({
                "date_added": cve.get("cisaExploitAdd"),
                "required_action": cve.get("cisaRequiredAction"),
                "due_date": cve.get("cisaActionDue"),
            })
        return info

    def sync_kev(self) -> Dict[str, Any]:
        request = urllib.request.Request(
            CISA_KEV_FEED,
            headers={"Accept": "application/json", "User-Agent": "SecuritySuite/2.0 defensive-scanner"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            payload = json.load(response)
        items = payload.get("vulnerabilities")
        if not isinstance(items, list) or not items:
            raise ValueError("CISA KEV feed did not contain vulnerability records.")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.kev_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temporary.replace(self.kev_path)
        self._kev_payload = payload
        return {
            "source": "CISA Known Exploited Vulnerabilities catalog",
            "catalog_version": payload.get("catalogVersion"),
            "date_released": payload.get("dateReleased"),
            "count": len(items),
            "cache_path": str(self.kev_path),
        }

    def format_cve_writeup(self, cve_id: str, live: bool = False) -> str:
        return self.format_cve_record(self.get_cve_info(cve_id, live=live))

    def format_cve_record(self, info: Dict[str, Any]) -> str:
        if not info.get("found"):
            return f"# {info['cve']}\n\nNo record was available locally or from the requested source.\n"
        title = info.get("title") or info["cve"]
        cvss = info.get("cvss")
        score = f"CVSS {cvss}" if cvss is not None else "no CVSS score in the loaded data; run with --live"
        lines = [
            f"# {info['cve']} - {title}" if title != info["cve"] else f"# {info['cve']}",
            "",
            f"**Severity:** {info.get('severity', 'UNKNOWN')} ({score})",
            f"**Known exploited:** {'yes' if info.get('known_exploited') else 'not confirmed in the loaded data'}",
            "",
            "**What it is**",
            info.get("plain") or info.get("description") or "No description available.",
            "",
            "**Affected scope**",
            info.get("affected") or self._derived_affected(info),
            "",
            "**Why it matters**",
            info.get("business_risk") or self._derived_risk(info),
            "",
            "**Defensive checks**",
        ]
        lines.extend(f"- {item}" for item in info.get("detection") or self._derived_checks(info))
        lines.extend(["", "**Remediation**"])
        lines.extend(f"- {item}" for item in info.get("mitigation") or self._derived_remediation(info))
        lines.extend(["", "**References**"])
        lines.extend(f"- {url}" for url in self._references(info))
        lines.append("")
        if info.get("live_error"):
            lines.extend([f"_Live NVD lookup failed ({info['live_error']}); this brief uses offline data._", ""])
        lines.extend([
            "This record intentionally excludes exploit payloads. Confirm affected versions with NVD and the vendor advisory before remediation.",
            "",
        ])
        return "\n".join(lines)

    def format_port_writeup(self, port: int) -> str:
        info = self.get_port_info(port)
        return (
            f"# Port {info['port']} - {info['service']}\n\n"
            f"**Service:** {info['service']}\n"
            f"**MITRE:** {info.get('technique') or 'n/a'} ({info.get('label')})\n\n"
            "This is a service mapping, not a vulnerability result. Confirm reachability, product, and version.\n"
        )

    def kev_status(self) -> Dict[str, Any]:
        items = self._kev_items()
        return {
            "loaded": bool(items),
            "count": len(items),
            "catalog_version": self._kev_payload.get("catalogVersion") if self._kev_payload else None,
            "date_released": self._kev_payload.get("dateReleased") if self._kev_payload else None,
        }

    def _load_kev_cache(self) -> Dict[str, Any]:
        try:
            payload = json.loads(self.kev_path.read_text(encoding="utf-8"))
            return payload if isinstance(payload.get("vulnerabilities"), list) else {}
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}

    def _kev_items(self) -> Iterable[Dict[str, Any]]:
        return (self._kev_payload or {}).get("vulnerabilities", [])

    def _offline_cve(
        self,
        key: str,
        local: Dict[str, Any] | None,
        kev_item: Dict[str, Any] | None,
    ) -> Dict[str, Any]:
        if local:
            info = {"cve": key, "found": True, "severity": _severity(local.get("cvss")), "source": "local curated record", **local}
            if kev_item:
                info.update(self._kev_fields(kev_item))
            return info
        if kev_item:
            return self._kev_to_info(kev_item)
        return {"cve": key, "found": False, "note": "Not found in the local or cached CISA catalog.", "source": "offline"}

    def _kev_to_info(self, item: Dict[str, Any], summary_only: bool = False) -> Dict[str, Any]:
        info = {
            "cve": item.get("cveID"),
            "found": True,
            "title": item.get("vulnerabilityName") or item.get("cveID"),
            "severity": "KNOWN EXPLOITED",
            "cvss": None,
            "known_exploited": True,
            "vendor": item.get("vendorProject"),
            "product": item.get("product"),
            "date_added": item.get("dateAdded"),
            "due_date": item.get("dueDate"),
            "source": "CISA KEV cache",
        }
        if not summary_only:
            info.update({
                "description": item.get("shortDescription"),
                "plain": item.get("shortDescription"),
                "required_action": item.get("requiredAction"),
                "known_ransomware_use": item.get("knownRansomwareCampaignUse"),
                "notes": item.get("notes"),
                "cwe": item.get("cwes") or [],
            })
        return info

    @staticmethod
    def _kev_fields(item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "known_exploited": True,
            "vendor": item.get("vendorProject"),
            "product": item.get("product"),
            "date_added": item.get("dateAdded"),
            "due_date": item.get("dueDate"),
            "required_action": item.get("requiredAction"),
            "known_ransomware_use": item.get("knownRansomwareCampaignUse"),
            "notes": item.get("notes"),
        }

    # Brief sections derived from KEV/NVD fields when no curated record exists.

    @staticmethod
    def _product_name(info: Dict[str, Any]) -> str | None:
        vendor, product = info.get("vendor"), info.get("product")
        if vendor and product:
            return product if product.lower().startswith(vendor.lower()) else f"{vendor} {product}"
        return product or vendor

    def _derived_affected(self, info: Dict[str, Any]) -> str:
        product = self._product_name(info)
        if product:
            return f"{product}. Confirm exact affected versions with NVD and the vendor advisory."
        return "Not listed in the loaded data. Confirm affected products and versions with NVD and the vendor advisory."

    @staticmethod
    def _derived_risk(info: Dict[str, Any]) -> str:
        parts = []
        if info.get("cvss") is not None:
            parts.append(f"Rated {info.get('severity', 'UNKNOWN')} with a CVSS score of {info['cvss']}.")
        if info.get("known_exploited"):
            added = f" on {info['date_added']}" if info.get("date_added") else ""
            parts.append(f"CISA added it to the Known Exploited Vulnerabilities catalog{added}, so attackers are using it.")
            if info.get("due_date"):
                parts.append(f"US federal agencies were required to remediate by {info['due_date']}.")
        if str(info.get("known_ransomware_use", "")).lower() == "known":
            parts.append("CISA reports known use in ransomware campaigns.")
        if not info.get("known_exploited"):
            parts.append("Exploitation is not confirmed in the loaded data; prioritize by exposure and severity.")
        return " ".join(parts)

    def _derived_checks(self, info: Dict[str, Any]) -> List[str]:
        product = self._product_name(info) or "the affected product"
        checks = [
            f"Do we run {product}? List every instance and its installed version.",
            "Which of those versions does the vendor advisory list as affected?",
        ]
        if info.get("known_exploited"):
            checks.append("Was any affected instance internet-facing while unpatched? If so, review its logs for signs of compromise.")
        return checks

    @staticmethod
    def _derived_remediation(info: Dict[str, Any]) -> List[str]:
        steps = []
        if info.get("required_action"):
            steps.append(f"CISA required action: {info['required_action']}")
        steps.append("Apply the vendor's fixed release or documented mitigation to every affected instance.")
        if info.get("known_exploited"):
            steps.append("Treat unpatched, internet-facing instances as possibly compromised until checked.")
        return steps

    @staticmethod
    def _is_exploit_reference(row: Dict[str, Any]) -> bool:
        url = str(row.get("url", "")).lower()
        return "Exploit" in (row.get("tags") or []) or any(host in url for host in EXPLOIT_HOSTS)

    @staticmethod
    def _references(info: Dict[str, Any], limit: int = 6) -> List[str]:
        urls = [f"https://nvd.nist.gov/vuln/detail/{info['cve']}"]
        urls.extend(re.findall(r"https?://[^\s,;\]]+", info.get("notes") or ""))
        urls.extend(info.get("references") or [])
        return list(dict.fromkeys(url.rstrip(".") for url in urls))[:limit]

    @staticmethod
    def _summary(cve_id: str, info: Dict[str, Any], source: str) -> Dict[str, Any]:
        return {
            "cve": cve_id,
            "title": info.get("title", cve_id),
            "cvss": info.get("cvss"),
            "severity": _severity(info.get("cvss")),
            "known_exploited": bool(info.get("known_exploited")),
            "date_added": info.get("date_added"),
            "source": source,
        }

    @staticmethod
    def _extract_cvss(metrics: Dict[str, Any]) -> tuple[float | None, str, str | None]:
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            rows = metrics.get(key) or []
            if rows:
                data = rows[0].get("cvssData", {})
                score = data.get("baseScore")
                severity = data.get("baseSeverity") or rows[0].get("baseSeverity") or _severity(score)
                return score, str(severity).upper(), data.get("vectorString")
        return None, "UNKNOWN", None

    @staticmethod
    def _validate_cve(cve_id: str) -> str:
        key = cve_id.strip().upper()
        if not CVE_PATTERN.fullmatch(key):
            raise ValueError("CVE IDs must look like CVE-2024-12345.")
        return key
