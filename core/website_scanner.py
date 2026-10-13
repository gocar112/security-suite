"""Passive website security-header and TLS scanner."""

from __future__ import annotations

import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.message import Message
from typing import Any, Dict, List


class WebsiteScanner:
    """Inspect a URL without submitting forms, fuzzing, or exploiting it."""

    MAX_BODY = 1_048_576

    def __init__(self, timeout: int = 15) -> None:
        self.timeout = max(1, min(int(timeout), 60))

    def scan(self, url: str) -> Dict[str, Any]:
        normalized = self._validate_url(url)
        started = datetime.now(timezone.utc)
        tls_info = self._inspect_tls(normalized) if normalized.startswith("https://") else None
        verification_error = None
        try:
            response, body = self._request(normalized, verify_tls=True)
        except ssl.SSLCertVerificationError as exc:
            verification_error = str(exc)
            response, body = self._request(normalized, verify_tls=False)
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLCertVerificationError):
                verification_error = str(exc.reason)
                response, body = self._request(normalized, verify_tls=False)
            else:
                raise RuntimeError(f"Website request failed: {exc.reason}") from exc

        findings = self._analyze_response(
            original_url=normalized,
            final_url=response.geturl(),
            status=response.status,
            headers=response.headers,
            body=body,
            tls_info=tls_info,
            verification_error=verification_error,
        )
        summary = self._summarize(findings)
        score = max(0, 100 - summary["high"] * 18 - summary["medium"] * 8 - summary["low"] * 3)
        completed = datetime.now(timezone.utc)
        return {
            "scan_type": "website_passive",
            "timestamp": started.isoformat(),
            "completed_at": completed.isoformat(),
            "duration_seconds": round((completed - started).total_seconds(), 3),
            "status": "completed",
            "url": normalized,
            "final_url": response.geturl(),
            "http_status": response.status,
            "score": score,
            "summary": summary,
            "findings": findings,
            "checks": findings,
            "limitations": [
                "Passive scan only: one GET request plus a TLS certificate inspection.",
                "No authentication, crawling, form submission, fuzzing, or exploit payloads are used.",
                "A clean result does not replace code review, dependency scanning, or an authorized penetration test.",
            ],
        }

    def _request(self, url: str, verify_tls: bool) -> tuple[Any, bytes]:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.2",
                "User-Agent": "SecuritySuite/2.0 passive-defense-scanner",
            },
            method="GET",
        )
        context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
        response = urllib.request.urlopen(request, timeout=self.timeout, context=context)
        body = response.read(self.MAX_BODY + 1)
        if len(body) > self.MAX_BODY:
            body = body[: self.MAX_BODY]
        return response, body

    def _inspect_tls(self, url: str) -> Dict[str, Any]:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port or 443
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=hostname) as secure_socket:
                    certificate = secure_socket.getpeercert()
                    return {
                        "valid": True,
                        "protocol": secure_socket.version(),
                        "cipher": secure_socket.cipher()[0] if secure_socket.cipher() else None,
                        "expires": certificate.get("notAfter"),
                        "issuer": dict(item[0] for item in certificate.get("issuer", ())).get("organizationName"),
                    }
        except (OSError, ssl.SSLError, ValueError) as exc:
            return {"valid": False, "error": str(exc)}

    def _analyze_response(
        self,
        original_url: str,
        final_url: str,
        status: int,
        headers: Message,
        body: bytes,
        tls_info: Dict[str, Any] | None,
        verification_error: str | None,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        lowered = {key.lower(): value for key, value in headers.items()}
        parsed = urllib.parse.urlsplit(final_url)
        is_local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        is_html = "text/html" in lowered.get("content-type", "").lower()

        def add(check_id: str, title: str, status_name: str, severity: str, evidence: str, remediation: str) -> None:
            findings.append({
                "id": check_id,
                "title": title,
                "category": "website security",
                "status": status_name,
                "severity": severity,
                "evidence": evidence,
                "remediation": remediation,
                "patch_id": None,
            })

        if status < 400:
            add("http-status", "Website responds successfully", "pass", "NONE", f"HTTP {status} returned from {final_url}.", "No action required.")
        else:
            add("http-status", "Website responds successfully", "fail", "MEDIUM", f"HTTP {status} returned from {final_url}.", "Fix the route or upstream service before security verification.")

        if parsed.scheme == "https":
            if verification_error or not (tls_info or {}).get("valid"):
                detail = verification_error or (tls_info or {}).get("error") or "Certificate verification failed."
                add("tls", "TLS certificate validates", "fail", "HIGH", detail, "Install a valid certificate with the complete chain and correct hostname.")
            else:
                add("tls", "TLS certificate validates", "pass", "NONE", f"{tls_info.get('protocol')} with certificate expiry {tls_info.get('expires')}.", "No action required.")
        elif is_local:
            add("https", "HTTPS used for remote traffic", "info", "INFO", "The target is loopback HTTP, which is acceptable for this local-only console.", "Keep the service bound to loopback.")
        else:
            add("https", "HTTPS used for remote traffic", "fail", "HIGH", f"Final URL uses {parsed.scheme or 'no'} encryption.", "Redirect HTTP to HTTPS and serve a valid TLS certificate.")

        hsts = lowered.get("strict-transport-security")
        if parsed.scheme == "https":
            if hsts:
                add("hsts", "HSTS enabled", "pass", "NONE", hsts, "No action required.")
            else:
                add("hsts", "HSTS enabled", "fail", "MEDIUM", "Strict-Transport-Security is missing.", "Add HSTS after every subdomain is ready for HTTPS.")

        csp = lowered.get("content-security-policy")
        if csp:
            add("csp", "Content Security Policy present", "pass", "NONE", csp, "Review the policy periodically and avoid unsafe-inline where possible.")
        elif is_html:
            add("csp", "Content Security Policy present", "fail", "MEDIUM", "No Content-Security-Policy header was returned.", "Define a restrictive policy for scripts, styles, connections, framing, and forms.")

        nosniff = lowered.get("x-content-type-options", "").lower()
        if nosniff == "nosniff":
            add("nosniff", "MIME sniffing disabled", "pass", "NONE", "X-Content-Type-Options: nosniff", "No action required.")
        else:
            add("nosniff", "MIME sniffing disabled", "fail", "LOW", "X-Content-Type-Options is missing or invalid.", "Return X-Content-Type-Options: nosniff.")

        frame_options = lowered.get("x-frame-options", "").lower()
        frame_ancestors = "frame-ancestors" in (csp or "").lower()
        if frame_ancestors or frame_options in {"deny", "sameorigin"}:
            add("framing", "Clickjacking protection present", "pass", "NONE", csp if frame_ancestors else f"X-Frame-Options: {frame_options}", "No action required.")
        elif is_html:
            add("framing", "Clickjacking protection present", "fail", "MEDIUM", "No frame-ancestors policy or valid X-Frame-Options header was found.", "Set CSP frame-ancestors and optionally X-Frame-Options for legacy clients.")

        referrer = lowered.get("referrer-policy")
        if referrer:
            add("referrer", "Referrer data constrained", "pass", "NONE", f"Referrer-Policy: {referrer}", "No action required.")
        elif is_html:
            add("referrer", "Referrer data constrained", "fail", "LOW", "Referrer-Policy is missing.", "Set strict-origin-when-cross-origin or a stricter policy.")

        permissions = lowered.get("permissions-policy")
        if permissions:
            add("permissions", "Browser capabilities constrained", "pass", "NONE", f"Permissions-Policy: {permissions}", "No action required.")
        elif is_html:
            add("permissions", "Browser capabilities constrained", "warn", "LOW", "Permissions-Policy is missing.", "Disable browser capabilities the application does not use.")

        cors_origin = lowered.get("access-control-allow-origin")
        cors_credentials = lowered.get("access-control-allow-credentials", "").lower()
        if cors_origin == "*" and cors_credentials == "true":
            add("cors", "CORS policy is not dangerously broad", "fail", "HIGH", "Wildcard origin is combined with credentialed CORS.", "Allow only explicit trusted origins and avoid credentialed wildcard behavior.")
        elif cors_origin == "*":
            add("cors", "CORS policy is not dangerously broad", "warn", "LOW", "Access-Control-Allow-Origin is wildcard.", "Confirm every returned resource is intentionally public.")
        else:
            add("cors", "CORS policy is not dangerously broad", "pass", "NONE", cors_origin or "No cross-origin access header was returned.", "No action required.")

        cookie_headers = headers.get_all("Set-Cookie", [])
        insecure_cookies = []
        for cookie in cookie_headers:
            name = cookie.split("=", 1)[0].strip() or "unnamed"
            lower_cookie = cookie.lower()
            problems = []
            if parsed.scheme == "https" and "; secure" not in lower_cookie:
                problems.append("Secure")
            if "; httponly" not in lower_cookie:
                problems.append("HttpOnly")
            if "samesite=" not in lower_cookie:
                problems.append("SameSite")
            if problems:
                insecure_cookies.append(f"{name} missing {', '.join(problems)}")
        if insecure_cookies:
            add("cookies", "Cookies use defensive attributes", "fail", "MEDIUM", "; ".join(insecure_cookies[:10]), "Set Secure, HttpOnly, and an appropriate SameSite attribute on session cookies.")
        elif cookie_headers:
            add("cookies", "Cookies use defensive attributes", "pass", "NONE", f"Checked {len(cookie_headers)} Set-Cookie header(s).", "No action required.")

        server = lowered.get("server", "")
        if server and re.search(r"\d", server):
            add("server-banner", "Server banner minimizes version detail", "warn", "LOW", f"Server: {server}", "Remove unnecessary product version details from response headers.")
        else:
            add("server-banner", "Server banner minimizes version detail", "pass", "NONE", server or "No Server header was returned.", "No action required.")

        if parsed.scheme == "https" and re.search(rb"(?:src|href)\s*=\s*['\"]http://", body, re.IGNORECASE):
            add("mixed-content", "Page avoids HTTP subresources", "fail", "MEDIUM", "An HTTP src or href was found in the HTTPS response body.", "Load active resources over HTTPS or use same-origin relative URLs.")
        elif is_html:
            add("mixed-content", "Page avoids obvious HTTP subresources", "pass", "NONE", "No obvious HTTP src or href was found in the inspected response.", "No action required.")

        if original_url != final_url:
            add("redirect", "Redirect destination recorded", "info", "INFO", f"{original_url} redirected to {final_url}.", "Confirm the destination is intentional.")
        return findings

    @staticmethod
    def _summarize(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "pass": 0, "error": 0, "info": 0, "total": len(findings), "actionable": 0, "patchable": 0}
        for finding in findings:
            status = finding["status"]
            severity = finding["severity"].lower()
            if status == "pass":
                summary["pass"] += 1
            elif status in {"info", "error"}:
                summary[status] += 1
            elif severity in summary:
                summary[severity] += 1
                summary["actionable"] += 1
        return summary

    @staticmethod
    def _validate_url(url: str) -> str:
        value = url.strip()
        if len(value) > 2048:
            raise ValueError("URL is too long.")
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Website URL must start with http:// or https://.")
        if not parsed.hostname:
            raise ValueError("Website URL must include a hostname.")
        if parsed.username or parsed.password:
            raise ValueError("Credentials are not accepted in website URLs.")
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("Website URL contains an invalid port.") from exc
        return value
