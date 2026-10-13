"""Security Suite command-line entry point and local dashboard launcher."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Dict, Iterable

from core.ids_detector import IDSDetector
from core.logger import get_logger, setup_logging
from core.malware_scanner import MalwareScanner
from core.patch_manager import build_patch_script
from core.system_scanner import SystemScanner
from core.threat_intel import ThreatIntelligence
from core.vuln_scanner import VulnerabilityScanner
from core.website_scanner import WebsiteScanner

__version__ = "2.0.0"
logger = get_logger(__name__)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Security Suite - defensive Windows, website, and private-network scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security_suite.py serve
  python security_suite.py system-scan --profile quick --output json
  python security_suite.py website-scan --url https://example.com
  python security_suite.py vuln-scan --target 192.168.1.10 --quick
  python security_suite.py info --cve CVE-2023-23397 --live

Only scan systems you own or are authorized to assess.
        """,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--log-file", help="Save diagnostic logs to a UTF-8 file")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    serve_parser = subparsers.add_parser("serve", help="Open the local security dashboard")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Loopback host only (default: 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, default=8766, help="Preferred local port (default: 8766; tries nearby ports if busy)")
    serve_parser.add_argument("--no-browser", action="store_true", help="Do not open the default browser")
    serve_parser.set_defaults(func=cmd_serve)
    serve_parser.add_argument("--write-runtime", action="store_true", help=argparse.SUPPRESS)

    launch_parser = subparsers.add_parser("launch", help="Start the dashboard in the background or reopen it")
    launch_parser.add_argument("--port", type=int, default=8766)
    launch_parser.add_argument("--no-browser", action="store_true")
    launch_parser.set_defaults(func=cmd_launch)

    system_parser = subparsers.add_parser("system-scan", help="Assess this Windows PC")
    system_parser.add_argument("--profile", choices=["quick", "full"], default="quick", help="Full also queries Windows Update")
    add_output_arguments(system_parser)
    system_parser.set_defaults(func=cmd_system_scan)

    web_parser = subparsers.add_parser("website-scan", help="Passively inspect website headers and TLS")
    web_parser.add_argument("--url", required=True, help="HTTP or HTTPS URL")
    web_parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    add_output_arguments(web_parser)
    web_parser.set_defaults(func=cmd_website_scan)

    vuln_parser = subparsers.add_parser("vuln-scan", help="Scan private targets for exposed TCP services")
    vuln_parser.add_argument("--target", required=True, help="Private IP, hostname, or CIDR range")
    vuln_parser.add_argument("--ports", default="1-1024", help="Ports such as 443, 80,443, or 1-1024")
    vuln_parser.add_argument("--quick", action="store_true", help="Scan a built-in list of common ports")
    vuln_parser.add_argument("--timeout", type=float, default=0.75, help="Per-port timeout in seconds")
    vuln_parser.add_argument("--allow-public", action="store_true", help="Allow an explicitly authorized public target")
    add_output_arguments(vuln_parser)
    vuln_parser.set_defaults(func=cmd_vuln_scan)

    malware_parser = subparsers.add_parser("malware-scan", help="Start an installed malware scanner")
    malware_parser.add_argument("--provider", choices=["defender", "malwarebytes"], default="defender")
    malware_parser.add_argument("--scan-type", choices=["quick", "full"], default="quick")
    malware_parser.set_defaults(func=cmd_malware_scan)

    intel_parser = subparsers.add_parser("intel-sync", help="Refresh the CISA Known Exploited Vulnerabilities cache")
    intel_parser.set_defaults(func=cmd_intel_sync)

    info_parser = subparsers.add_parser("info", help="Look up defensive vulnerability intelligence")
    info_parser.add_argument("--cve", help="CVE identifier")
    info_parser.add_argument("--port", type=int, help="Port and MITRE service mapping")
    info_parser.add_argument("--list", action="store_true", help="List local and cached CVE records")
    info_parser.add_argument("--live", action="store_true", help="Query the NIST NVD API for the CVE")
    info_parser.add_argument("--outfile", help="Save the writeup to a markdown file")
    info_parser.set_defaults(func=cmd_info)

    audit_parser = subparsers.add_parser("audit", help="Run system posture and private-network checks")
    audit_parser.add_argument("--target", default="127.0.0.1", help="Private network target (default: localhost)")
    audit_parser.add_argument("--profile", choices=["quick", "full"], default="quick")
    audit_parser.add_argument("--website", help="Optional website URL for passive checks")
    add_output_arguments(audit_parser)
    audit_parser.set_defaults(func=cmd_audit)

    ids_parser = subparsers.add_parser("ids-detect", help="Show IDS capability status (capture is not implemented)")
    ids_parser.add_argument("--interface", help="Requested interface")
    ids_parser.add_argument("--duration", type=int, default=60, help="Requested monitoring duration")
    ids_parser.add_argument("--pcap", help="Requested PCAP path")
    add_output_arguments(ids_parser, formats=("json", "text"))
    ids_parser.set_defaults(func=cmd_ids_detect)

    check_parser = subparsers.add_parser("self-check", help="Verify imports and local logic without scanning")
    check_parser.set_defaults(func=cmd_self_check)
    return parser


def add_output_arguments(parser: argparse.ArgumentParser, formats: Iterable[str] = ("json", "csv", "text")) -> None:
    parser.add_argument("--output", choices=list(formats), default="text", help="Output format")
    parser.add_argument("--outfile", help="Save results to a file")


def cmd_serve(args: argparse.Namespace) -> None:
    from core.web_server import serve_dashboard

    serve_dashboard(host=args.host, port=args.port, open_browser=not args.no_browser, version=__version__, write_runtime=args.write_runtime)


def cmd_launch(args: argparse.Namespace) -> None:
    from core.launcher import launch_dashboard

    record = launch_dashboard(port=args.port, open_browser=not args.no_browser)
    print(f"Security Suite dashboard: {record['url']}")
    print("Running in the background. Run this launcher again to reopen the same dashboard.")


def cmd_system_scan(args: argparse.Namespace) -> Dict[str, Any]:
    logger.info("Starting %s Windows posture scan", args.profile)
    return emit_results(SystemScanner().scan(profile=args.profile), args, "system_posture")


def cmd_website_scan(args: argparse.Namespace) -> Dict[str, Any]:
    logger.info("Starting passive website scan on %s", args.url)
    return emit_results(WebsiteScanner(timeout=args.timeout).scan(args.url), args, "website_passive")


def cmd_vuln_scan(args: argparse.Namespace) -> Dict[str, Any]:
    logger.info("Starting private-network exposure scan on %s", args.target)
    scanner = VulnerabilityScanner(timeout=args.timeout, allow_public=args.allow_public)
    results = scanner.scan(target=args.target, quick=args.quick, port_range=None if args.quick else args.ports)
    return emit_results(results, args, "network_exposure")


def cmd_malware_scan(args: argparse.Namespace) -> Dict[str, Any]:
    scanner = MalwareScanner()
    if args.provider == "defender":
        result = scanner.start_defender_scan(args.scan_type)
    else:
        if args.scan_type == "full":
            raise ValueError("Malwarebytes scan depth is configured in the licensed product, not by Security Suite.")
        result = scanner.launch_malwarebytes(scan=True)
    print(json.dumps(result, indent=2))
    return result


def cmd_intel_sync(args: argparse.Namespace) -> Dict[str, Any]:
    del args
    result = ThreatIntelligence().sync_kev()
    print(json.dumps(result, indent=2))
    return result


def cmd_info(args: argparse.Namespace) -> Dict[str, Any] | None:
    intel = ThreatIntelligence()
    if args.list:
        rows = intel.list_cves()
        output = "# Vulnerability intelligence\n\n" + "\n".join(
            f"- {row['cve']}  {row['severity']} - {row['title']}" for row in rows
        ) + "\n"
        result: Dict[str, Any] = {"records": rows, "kev": intel.kev_status()}
    elif args.cve:
        result = intel.get_cve_info(args.cve, live=args.live)
        output = intel.format_cve_writeup(args.cve, live=args.live)
    elif args.port:
        result = intel.get_port_info(args.port)
        output = intel.format_port_writeup(args.port)
    else:
        raise ValueError("Use --cve <CVE-ID>, --port <PORT>, or --list.")
    if args.outfile:
        save_results(args.outfile, output)
        logger.info("Writeup saved to %s", args.outfile)
    print(output)
    return result


def cmd_audit(args: argparse.Namespace) -> Dict[str, Any]:
    report = {
        "scan_type": "security_audit",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": args.target,
        "modules": {
            "system": SystemScanner().scan(profile=args.profile),
            "network": VulnerabilityScanner(timeout=0.5).scan(target=args.target, quick=True),
        },
    }
    if args.website:
        report["modules"]["website"] = WebsiteScanner().scan(args.website)
    return emit_results(report, args, "security_audit")


def cmd_ids_detect(args: argparse.Namespace) -> Dict[str, Any]:
    result = IDSDetector().detect(interface=args.interface, duration=args.duration, pcap_file=args.pcap)
    return emit_results(result, args, "ids_status")


def cmd_self_check(args: argparse.Namespace) -> Dict[str, Any]:
    del args
    from core.web_server import SecuritySuiteApp, create_server

    intel = ThreatIntelligence()
    patch = build_patch_script(["disable_llmnr"])
    server = create_server(port=0, app=SecuritySuiteApp(version=__version__))
    server.server_close()
    checks = {
        "threat_intel_port_443": intel.get_port_info(443).get("service") == "https",
        "threat_intel_cve": intel.get_cve_info("CVE-2021-44228").get("found") is True,
        "patch_allowlist": "EnableMulticast" in patch and "Invoke-Expression" not in patch,
        "dashboard_loopback": True,
        "ids_reports_limitation": IDSDetector().detect().get("status") == "skipped",
    }
    failed = [name for name, passed in checks.items() if not passed]
    report = {
        "scan_type": "self_check",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "failed" if failed else "ok",
        "version": __version__,
        "checks": checks,
        "failed": failed,
    }
    print(format_text(report, "self_check"))
    if failed:
        raise RuntimeError("Self-check failed: " + ", ".join(failed))
    return report


def emit_results(results: Dict[str, Any], args: argparse.Namespace, report_type: str) -> Dict[str, Any]:
    output = format_output(results, args.output, report_type)
    if args.outfile:
        save_results(args.outfile, output)
        logger.info("Results saved to %s", args.outfile)
    else:
        print(output)
    return results


def format_output(results: Dict[str, Any], output_format: str, report_type: str) -> str:
    if output_format == "json":
        return json.dumps(results, indent=2)
    if output_format == "csv":
        return format_csv(results)
    return format_text(results, report_type)


def format_text(results: Dict[str, Any], report_type: str) -> str:
    lines = ["", "=" * 72, f"SECURITY SUITE - {report_type.replace('_', ' ').upper()}", "=" * 72]
    for key in ("timestamp", "completed_at", "status", "target", "url", "score"):
        if key in results:
            lines.append(f"{key.replace('_', ' ').title()}: {results[key]}")
    summary = results.get("summary")
    if isinstance(summary, dict):
        lines.append("Summary: " + ", ".join(f"{key}={value}" for key, value in summary.items()))
    rows = results.get("checks") or results.get("findings") or results.get("vulnerabilities") or []
    if not isinstance(rows, list):
        rows = []
    if rows:
        lines.extend(["", "Findings:"])
        for row in rows:
            title = row.get("title") or row.get("description") or row.get("id") or "Finding"
            lines.append(f"- [{row.get('severity', 'INFO')}] {title}")
            if row.get("evidence"):
                lines.append(f"  Evidence: {row['evidence']}")
            if row.get("remediation"):
                lines.append(f"  Response: {row['remediation']}")
    if report_type == "security_audit":
        lines.extend(["", json.dumps(results.get("modules", {}), indent=2)])
    lines.append("=" * 72)
    return "\n".join(lines)


def format_csv(results: Dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["ID", "Status", "Severity", "Category", "Title", "Evidence", "Remediation", "CVE", "Host", "Port"])
    rows = results.get("checks") or results.get("findings") or results.get("vulnerabilities") or []
    for row in rows:
        writer.writerow([
            row.get("id", ""),
            row.get("status", ""),
            row.get("severity", ""),
            row.get("category", ""),
            row.get("title", ""),
            row.get("evidence", row.get("description", "")),
            row.get("remediation", ""),
            row.get("cve", ""),
            row.get("host", ""),
            row.get("port", ""),
        ])
    return output.getvalue()


def save_results(filepath: str, content: str) -> None:
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main() -> None:
    parser = create_parser()
    args = parser.parse_args()
    # Windows consoles default to cp1252; NVD text can contain characters it cannot encode.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    setup_logging(level=logging.DEBUG if args.verbose else logging.INFO, logfile=args.log_file)
    if not hasattr(args, "func"):
        parser.print_help()
        return
    try:
        args.func(args)
    except KeyboardInterrupt:
        logger.info("Stopped by user")
    except Exception as exc:
        logger.error("%s", exc, exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
