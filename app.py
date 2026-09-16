"""NexusAudit local web application.

Run with: python app.py
Then open http://127.0.0.1:8000/

The scanner only performs a safe, single GET request against a public HTTP(S)
target. It does not crawl, brute-force, exploit, or modify the target.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
MAX_BODY_BYTES = 1_048_576


def validate_target(value: str) -> tuple[str, str]:
    target = value.strip()
    if not target:
        raise ValueError("A target URL is required.")
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be a valid http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not allowed.")
    if parsed.port and not 1 <= parsed.port <= 65535:
        raise ValueError("Target port is invalid.")
    host = parsed.hostname
    try:
        addresses = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise ValueError("The target hostname could not be resolved.") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise ValueError("Private, loopback, and non-public targets are blocked.")
    return target, host


def finding(finding_id: str, title: str, severity: str, finding_type: str,
            description: str, impact: str, exploit: str, remediation: str) -> dict:
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "type": finding_type,
        "description": description,
        "impact": impact,
        "exploit": exploit,
        "remediation": remediation,
    }


def scan_target(raw_target: str) -> dict:
    target, domain = validate_target(raw_target)
    parsed = urlparse(target)
    request = Request(target, headers={"User-Agent": "NexusAudit/1.0 (authorized-audit)"})
    try:
        with urlopen(request, timeout=8) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            status = response.status
            final_url = response.geturl()
            response.read(MAX_BODY_BYTES)
    except HTTPError as exc:
        headers = {key.lower(): value for key, value in exc.headers.items()}
        status = exc.code
        final_url = target
    except (URLError, TimeoutError, OSError) as exc:
        raise ValueError(f"Target could not be reached: {exc.reason if hasattr(exc, 'reason') else exc}") from exc

    vulnerabilities = []
    if parsed.scheme != "https":
        vulnerabilities.append(finding(
            "http-only", "No HTTPS Encryption", "critical", "Transport Security",
            "The target is available over plaintext HTTP.", "Credential theft and traffic interception.",
            "An on-path attacker can inspect or alter plaintext requests.",
            "Redirect all traffic to HTTPS and install a valid TLS certificate.",
        ))
    if "content-security-policy" not in headers:
        vulnerabilities.append(finding(
            "missing-csp", "Missing Content Security Policy", "high", "Injection Protection",
            "No Content-Security-Policy response header was observed.",
            "XSS impact is broader when script sources are not restricted.",
            "Review script injection paths in an authorized test environment.",
            "Add a restrictive Content-Security-Policy appropriate for the application.",
        ))
    if "strict-transport-security" not in headers and parsed.scheme == "https":
        vulnerabilities.append(finding(
            "missing-hsts", "Missing HSTS Header", "medium", "Transport Security",
            "No Strict-Transport-Security response header was observed.",
            "Users may be exposed to protocol downgrade attacks.",
            "A downgrade attempt can be made before a secure connection is established.",
            "Set Strict-Transport-Security with an appropriate max-age.",
        ))
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        vulnerabilities.append(finding(
            "missing-frame-protection", "Missing Frame Protection", "medium", "Clickjacking Protection",
            "Neither X-Frame-Options nor CSP frame-ancestors was observed.",
            "The page may be embedded and visually disguised by another site.",
            "An authorized tester can verify whether sensitive actions work in an iframe.",
            "Set X-Frame-Options or a CSP frame-ancestors directive.",
        ))
    if "referrer-policy" not in headers:
        vulnerabilities.append(finding(
            "missing-referrer-policy", "Missing Referrer-Policy", "low", "Privacy",
            "No Referrer-Policy response header was observed.",
            "URLs can disclose more navigation context than intended.",
            "Review whether sensitive path or query data is sent as a referrer.",
            "Set Referrer-Policy to strict-origin-when-cross-origin or stricter.",
        ))
    if "server" in headers or "x-powered-by" in headers:
        disclosed = headers.get("x-powered-by") or headers.get("server")
        vulnerabilities.append(finding(
            "technology-disclosure", "Technology Version Disclosure", "info", "Information Disclosure",
            f"The response identifies server technology ({disclosed}).",
            "Detailed version information helps attackers prioritize known issues.",
            "Fingerprinting can correlate disclosed versions with public advisories.",
            "Remove unnecessary version banners and keep the underlying software patched.",
        ))

    counts = {severity: sum(v["severity"] == severity for v in vulnerabilities)
              for severity in ("critical", "high", "medium", "low", "info")}
    score = max(0, 100 - counts["critical"] * 25 - counts["high"] * 15 -
                counts["medium"] * 8 - counts["low"] * 3)
    return {
        "target": target,
        "final_url": final_url,
        "domain": domain,
        "status": status,
        "headers_checked": len(headers),
        "vulnerabilities": vulnerabilities,
        "stats": {**counts, "score": score},
    }


def assistant_reply(message: str, findings: list[dict] | None = None) -> dict:
    """Return practical, deterministic guidance without requiring an API key."""
    prompt = message.strip().lower()
    findings = findings or []
    if not prompt:
        return {"reply": "Tell me what you want to fix, or select a finding from the report.", "related": []}
    if prompt in {"hi", "hello", "hey", "good morning", "good afternoon", "good evening"} or prompt.startswith(("hi ", "hello ", "hey ")):
        return {"reply": "Hi! I'm NexusAudit. I can explain your findings, review pasted source code, and help you prioritise defensive fixes. What would you like to check?", "related": []}
    if any(word in prompt for word in ("hack", "exploit", "break into", "attack")):
        return {"reply": "I cannot provide instructions to compromise Google or any third-party website. I can help you verify defenses on systems you own: review the finding, apply its remediation, and rerun the authorized header audit.", "related": [item["id"] for item in findings[:3]]}
    if findings:
        selected = next((item for item in findings if item["title"].lower() in prompt or item["id"].lower() in prompt), None)
        if selected:
            return {"reply": f"{selected['title']}: {selected['description']} Fix it by {selected['remediation']} Then rerun the audit to verify the response header.", "related": [selected["id"]]}
    if "score" in prompt or "result" in prompt:
        return {"reply": "Start with critical and high findings, then rerun the scan after deploying each fix. A score is a prioritisation signal, not proof that an application is secure.", "related": [item["id"] for item in findings[:3]]}
    if "happen" in prompt or "risk" in prompt or "not fixed" in prompt or "consequence" in prompt:
        if findings:
            item = findings[0]
            return {"reply": f"If {item['title']} remains unresolved, {item['impact']} Apply this remediation: {item['remediation']} Then rerun the audit to confirm the risk is reduced.", "related": [item["id"]]}
        return {"reply": "Run an audit first so I can explain the concrete consequence and remediation for each finding.", "related": []}
    if "csp" in prompt or "content security" in prompt:
        return {"reply": "Begin with a report-only policy, review violations, then enforce it. A safe baseline is: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'. Add only the script, style, image, and connection origins your app needs.", "related": ["missing-csp"]}
    if "hsts" in prompt or "https" in prompt or "ssl" in prompt:
        return {"reply": "Serve the application over HTTPS, redirect HTTP to HTTPS, and then add Strict-Transport-Security: max-age=31536000; includeSubDomains. Only include preload after confirming every subdomain supports HTTPS.", "related": ["http-only", "missing-hsts"]}
    if "frame" in prompt or "clickjack" in prompt:
        return {"reply": "Prevent framing with Content-Security-Policy: frame-ancestors 'none' (or 'self' when embedding is required). X-Frame-Options: DENY is a useful legacy fallback.", "related": ["missing-frame-protection"]}
    if "referrer" in prompt or "privacy" in prompt:
        return {"reply": "Set Referrer-Policy: strict-origin-when-cross-origin. Avoid putting secrets or personal data in URLs because headers cannot protect information already present in a query string.", "related": ["missing-referrer-policy"]}
    return {"reply": "I can explain the report, prioritise fixes, or suggest secure headers. Try asking “How do I fix CSP?” or “What should I fix first?”.", "related": [item["id"] for item in findings[:1]]}


def audit_code(source: str, filename: str = "pasted-code") -> dict:
    """Run a small, transparent static review over user-provided source code."""
    if not source.strip():
        raise ValueError("Paste code before running the code audit.")
    if len(source.encode("utf-8")) > 512_000:
        raise ValueError("Code input is limited to 512 KB.")
    checks = [
        ("hardcoded-secret", "Possible hardcoded secret", "critical",
         r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
         "Credentials in source can be copied from the repository or browser bundle.",
         "Move secrets to a server-side environment variable and rotate exposed credentials."),
        ("dangerous-html", "Unsafe HTML injection sink", "high",
         r"(?i)(innerHTML\s*=|document\.write\s*\()",
         "Untrusted content written as HTML can create cross-site scripting risk.",
         "Prefer textContent or a trusted sanitizer and validate untrusted input."),
        ("dynamic-code", "Dynamic code execution", "high",
         r"(?i)(eval\s*\(|new\s+Function\s*\()",
         "Dynamic code execution turns data flowing into this expression into executable code.",
         "Remove eval/new Function and use explicit data parsing or dispatch."),
        ("shell-exec", "Shell command execution", "high",
         r"(?i)(subprocess\.(run|Popen|call)|child_process\.(exec|spawn)|os\.system\s*\()",
         "Process execution needs strict argument handling and least privilege.",
         "Use fixed argument arrays, allowlists, timeouts, and avoid shell=True."),
        ("http-url", "Insecure HTTP URL", "medium",
         r"(?i)(['\"]http://|fetch\s*\(\s*['\"]http:)",
         "Plain HTTP can expose traffic to interception.",
         "Use HTTPS and reject insecure redirects for sensitive operations."),
        ("debug-mode", "Debug mode may be enabled", "medium",
         r"(?i)(debug\s*=\s*True|DEBUG\s*=\s*True|NODE_ENV\s*=\s*['\"]development)",
         "Verbose errors and debug tooling can disclose internals in production.",
         "Disable debug mode in production and configure it through deployment settings."),
        ("weak-cookie", "Cookie missing security attributes", "medium",
         r"(?i)(set-cookie|document\.cookie)",
         "Cookies should be protected against script access and cross-site requests.",
         "Set Secure, HttpOnly, and SameSite attributes on session cookies."),
    ]
    findings = []
    lines = source.splitlines()
    for finding_id, title, severity, pattern, impact, remediation in checks:
        import re
        matches = [index + 1 for index, line in enumerate(lines) if re.search(pattern, line)]
        if matches:
            findings.append(finding(finding_id, title, severity, "Source Review",
                                    f"Pattern found in {filename} at line(s): {', '.join(map(str, matches[:8]))}.",
                                    impact, "Review the flagged line in an authorized code review.", remediation))
    counts = {severity: sum(item["severity"] == severity for item in findings)
              for severity in ("critical", "high", "medium", "low", "info")}
    return {"filename": filename, "lines": len(lines), "vulnerabilities": findings,
            "stats": {**counts, "score": max(0, 100 - counts["critical"] * 25 -
                                             counts["high"] * 15 - counts["medium"] * 8)}}


def audit_project() -> dict:
    """Review source files in this application without requiring pasted code."""
    allowed = {".html", ".htm", ".js", ".mjs", ".css", ".py", ".json", ".yml", ".yaml"}
    ignored = {".git", ".venv", "node_modules", "__pycache__", "attachments"}
    files_checked = 0
    findings = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in allowed:
            continue
        if any(part in ignored for part in path.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            continue
        files_checked += 1
        report = audit_code(source, str(path.relative_to(ROOT)))
        findings.extend(report["vulnerabilities"])
    counts = {severity: sum(item["severity"] == severity for item in findings)
              for severity in ("critical", "high", "medium", "low", "info")}
    return {"project": ROOT.name, "files_checked": files_checked,
            "vulnerabilities": findings, "stats": {**counts, "score": max(
                0, 100 - counts["critical"] * 25 - counts["high"] * 15 - counts["medium"] * 8)}}


class NexusHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self) -> None:
        if self.path in {"/", "/index.html"}:
            self.path = "/scanner.html"
        if self.path == "/api/health":
            self.send_json({"status": "ok", "service": "NexusAudit"})
            return
        if self.path.startswith("/api/scan"):
            self.send_json({"error": "Use POST /api/scan with a JSON target."}, 405)
            return
        super().do_GET()

    def do_POST(self) -> None:
        if self.path == "/api/project-audit":
            try:
                self.send_json(audit_project())
            except OSError as exc:
                self.send_json({"error": f"Project audit failed: {exc}"}, 500)
            return
        if self.path == "/api/code-audit":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 550_000:
                    raise ValueError("Request body is too large.")
                payload = json.loads(self.rfile.read(length) or b"{}")
                self.send_json(audit_code(str(payload.get("code", "")), str(payload.get("filename", "pasted-code"))))
            except (ValueError, json.JSONDecodeError) as exc:
                self.send_json({"error": str(exc)}, 400)
            return
        if self.path == "/api/assistant":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 32_768:
                    raise ValueError("Request body is too large.")
                payload = json.loads(self.rfile.read(length) or b"{}")
                message = str(payload.get("message", ""))
                findings = payload.get("findings", [])
                if not isinstance(findings, list):
                    findings = []
                self.send_json(assistant_reply(message, findings))
            except (ValueError, json.JSONDecodeError) as exc:
                self.send_json({"error": str(exc)}, 400)
            return
        if self.path != "/api/scan":
            self.send_json({"error": "Not found."}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 16_384:
                raise ValueError("Request body is too large.")
            payload = json.loads(self.rfile.read(length) or b"{}")
            result = scan_target(str(payload.get("target", "")))
            self.send_json(result)
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except Exception as exc:
            self.send_json({"error": f"Scan failed: {exc}"}, 502)

    def send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        print(f"[NexusAudit] {self.address_string()} - {fmt % args}")


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8000), NexusHandler)
    print("NexusAudit running at http://127.0.0.1:8000/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
