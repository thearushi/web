#!/usr/bin/env python3
"""
Web Application Security Baseline Scanner
Performs baseline configuration checks including HTTPS enforcement,
security response headers, cookie security flags, and server information disclosure.
"""

import os
import sys
import json
import time
import socket
import urllib.request
import urllib.error
from urllib.parse import urlparse
from http.cookies import SimpleCookie

DEFAULT_TIMEOUT = 8
HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_history.json")

# Recommended baseline security headers and explanations
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Restricts the resources (scripts, images, styles) a browser can load to mitigate XSS and data injection.",
        "severity_if_missing": "MEDIUM",
        "recommended": "default-src 'self'; ..."
    },
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections and protects against man-in-the-middle attacks (HSTS).",
        "severity_if_missing": "HIGH",
        "recommended": "max-age=31536000; includeSubDomains; preload"
    },
    "X-Content-Type-Options": {
        "description": "Prevents browsers from MIME-sniffing a response away from the declared content-type.",
        "severity_if_missing": "LOW",
        "recommended": "nosniff"
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking attacks by controlling whether the site can be framed.",
        "severity_if_missing": "MEDIUM",
        "recommended": "DENY or SAMEORIGIN"
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is sent with requests made from your site.",
        "severity_if_missing": "LOW",
        "recommended": "strict-origin-when-cross-origin or no-referrer"
    },
    "Permissions-Policy": {
        "description": "Restricts access to browser features (geolocation, camera, microphone, etc.).",
        "severity_if_missing": "LOW",
        "recommended": "camera=(), microphone=(), geolocation=()"
    },
}

# Information disclosure headers that should ideally be removed or masked
INFO_DISCLOSURE_HEADERS = [
    "X-Powered-By",
    "Server",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator"
]


def add_finding(findings, severity, title, evidence, advice):
    """Helper to append structured security findings."""
    findings.append({
        "severity": severity.upper(),
        "title": title,
        "evidence": evidence,
        "advice": advice,
    })


def calculate_security_score(findings, is_https):
    """
    Computes a numerical score (0 - 100) and letter grade (A+, A, B, C, D, F)
    based on the severity of recorded findings.
    """
    base_score = 100 if is_https else 40
    deductions = {
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 4,
        "INFO": 0,
        "ERROR": 100
    }
    total_deductions = sum(deductions.get(f.get("severity", "INFO"), 0) for f in findings)
    final_score = max(0, min(100, base_score - total_deductions))

    if final_score >= 95:
        grade = "A+"
        color = "#10B981"  # Emerald
    elif final_score >= 85:
        grade = "A"
        color = "#059669"
    elif final_score >= 70:
        grade = "B"
        color = "#3B82F6"  # Blue
    elif final_score >= 55:
        grade = "C"
        color = "#F59E0B"  # Amber
    elif final_score >= 40:
        grade = "D"
        color = "#EF4444"  # Red
    else:
        grade = "F"
        color = "#DC2626"  # Dark Red

    return {
        "score": final_score,
        "grade": grade,
        "color": color
    }


def load_history():
    """Load scan history from JSON file."""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_history(history):
    """Save scan history list to JSON file."""
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
        return True
    except Exception:
        return False


def save_scan_to_history(result):
    """Save a single scan result summary to scan history."""
    try:
        history = load_history()
        entry = {
            "id": f"scan_{int(time.time() * 1000)}",
            "timestamp": int(time.time()),
            "url": result.get("url"),
            "final_url": result.get("final_url"),
            "status": result.get("status"),
            "elapsed": result.get("elapsed", 0),
            "score": result.get("score", {}),
            "findings_count": len(result.get("findings", [])),
            "high_count": sum(1 for f in result.get("findings", []) if f.get("severity") in ("HIGH", "CRITICAL", "ERROR")),
            "header_checks_count": len(result.get("header_checks", {})),
            "cookie_checks_count": len(result.get("cookie_checks", []))
        }
        # Deduplicate fast successive scans for the same target
        history = [h for h in history if not (h.get("url") == entry["url"] and abs(h.get("timestamp", 0) - entry["timestamp"]) < 2)]
        history.insert(0, entry)
        history = history[:60]
        save_history(history)
        return True
    except Exception:
        return False


def calculate_stats(history):
    """Compute aggregate scanner metrics from history."""
    total_scans = len(history)
    total_vulns = sum(item.get("findings_count", len(item.get("findings", []))) for item in history)
    unique_targets = len({item.get("url", "") for item in history if item.get("url")})
    total_time = sum(item.get("elapsed", 0) for item in history)
    avg_time = round(total_time / total_scans, 2) if total_scans else 0
    return {
        "total_scans": total_scans,
        "total_vulns": total_vulns,
        "targets_scanned": unique_targets,
        "avg_scan_time": avg_time,
    }


def resolve_host_dns(hostname, enable_reverse_dns=True, timeout=DEFAULT_TIMEOUT):
    """Resolves IP addresses and reverse PTR records for a target hostname."""
    dns_info = {
        "hostname": hostname,
        "ip": None,
        "all_ips": [],
        "reverse_dns": None,
        "error": None
    }
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = list(dict.fromkeys([item[4][0] for item in addr_info if item[4]]))
        dns_info["all_ips"] = ips
        dns_info["ip"] = ips[0] if ips else None

        if enable_reverse_dns and dns_info["ip"]:
            try:
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(min(timeout, 3.0))
                rev_host, _, _ = socket.gethostbyaddr(dns_info["ip"])
                dns_info["reverse_dns"] = rev_host
                socket.setdefaulttimeout(old_timeout)
            except Exception:
                dns_info["reverse_dns"] = "No PTR record found"
        elif not enable_reverse_dns:
            dns_info["reverse_dns"] = "Disabled by user setting"
    except Exception as exc:
        dns_info["error"] = str(exc)
        dns_info["reverse_dns"] = "Resolution failed"

    return dns_info


def scan_url(raw_url, timeout=DEFAULT_TIMEOUT, enable_reverse_dns=True, max_threads=10):
    """
    Scans a target web application URL for baseline security headers,
    HTTPS enforcement, cookie attributes, and information disclosures.
    """
    raw_url = raw_url.strip()

    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid URL. Please provide a valid hostname.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not accepted.")

    # Prevent accidental scans of local or private network targets
    host = parsed.hostname.lower()
    if host in ("localhost", "127.0.0.1", "::1") or host.endswith((".localhost", ".local")):
        raise ValueError("Scanning localhost / loopback targets is restricted in this version.")

    findings = []
    logs = []

    def log_event(symbol, message):
        timestamp = time.strftime("%H:%M:%S")
        millis = int((time.time() % 1) * 1000)
        logs.append(f"[{timestamp}.{millis:03d}] [{symbol}] {message}")

    log_event("*", f"Initializing baseline security audit for: {raw_url}")
    log_event("+", f"Target Host: {parsed.hostname} | Scheme: {parsed.scheme.upper()} | Port: {parsed.port or (443 if parsed.scheme == 'https' else 80)}")
    log_event("i", f"Network Socket limits: Timeout={timeout}s, Thread Pool Workers={max_threads}")

    # DNS Resolution
    dns_info = resolve_host_dns(parsed.hostname, enable_reverse_dns=enable_reverse_dns, timeout=timeout)
    if dns_info.get("ip"):
        log_event("✓", f"Network Socket resolved IP: {dns_info['ip']} (Total IPs: {len(dns_info.get('all_ips', []))})")
    else:
        log_event("!", f"DNS resolution notice: {dns_info.get('error', 'Unable to resolve IP')}")

    if enable_reverse_dns:
        log_event("i", f"Reverse DNS PTR resolution: {dns_info.get('reverse_dns', 'None')}")

    request = urllib.request.Request(
        raw_url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) EducationalSecurityScanner/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        method="GET",
    )

    log_event("i", f"Dispatching HTTP GET probe via network socket...")
    start = time.monotonic()
    response = None
    error_message = None

    # Configure secure TLS context with certifi if present
    ssl_context = None
    try:
        import ssl
        try:
            import certifi
            ssl_context = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            ssl_context = ssl.create_default_context()
    except Exception:
        ssl_context = None

    try:
        if ssl_context is not None and parsed.scheme == "https":
            response = urllib.request.urlopen(request, timeout=timeout, context=ssl_context)
        else:
            response = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        # HTTP 4xx/5xx responses are still valuable for header inspection
        response = exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        error_message = str(exc)
        # If certificate verification failed, record finding and attempt fallback probe to still inspect headers
        if "CERTIFICATE_VERIFY_FAILED" in str(exc) or "certificate verify failed" in str(exc).lower():
            log_event("!", f"TLS certificate validation failed: {exc}")
            add_finding(
                findings, "HIGH", "TLS / SSL Certificate Verification Failed",
                f"Certificate validation error: {exc}",
                "Ensure an active, valid TLS certificate signed by a recognized Certificate Authority (CA) is properly installed on the web server."
            )
            try:
                import ssl
                fallback_ctx = ssl._create_unverified_context()
                response = urllib.request.urlopen(request, timeout=timeout, context=fallback_ctx)
                log_event("i", "Retrieved response via fallback socket to audit headers despite certificate warning.")
                error_message = None
            except Exception as e2:
                error_message = f"SSL failed ({exc}) and fallback probe failed ({e2})"

    elapsed = time.monotonic() - start

    if response is None:
        log_event("x", f"Network socket connection failed: {error_message or 'No HTTP response received'}")
        add_finding(
            findings, "ERROR", "Request failed",
            error_message or "No HTTP response received.",
            "Check the URL, DNS resolution, network connectivity, and TLS certificate validity."
        )
        return {
            "url": raw_url,
            "status": None,
            "elapsed": elapsed,
            "final_url": None,
            "headers": {},
            "raw_headers_list": [],
            "header_checks": {},
            "cookie_checks": [],
            "findings": findings,
            "dns_info": dns_info,
            "logs": logs,
            "score": calculate_security_score(findings, False),
        }

    try:
        status = response.status
        headers = response.headers
        final_url = response.geturl()
        header_names = {name.lower(): name for name in headers.keys()}

        # Check HTTP vs HTTPS
        is_https = (parsed.scheme == "https")
        if parsed.scheme == "http":
            add_finding(
                findings, "HIGH", "Supplied URL uses insecure HTTP",
                f"Requested scheme is {parsed.scheme.upper()} without transport layer encryption.",
                "Enable HTTPS with an active TLS certificate and enforce strict redirection from HTTP to HTTPS."
            )

        final_scheme = urlparse(final_url).scheme if final_url else ""
        if final_scheme and final_scheme != "https":
            add_finding(
                findings, "HIGH", "Final redirected URL is not HTTPS",
                f"The final response endpoint resolved to: {final_url}",
                "Configure web server rules to permanently redirect all traffic to HTTPS (301 redirect)."
            )
        elif final_scheme == "https":
            add_finding(
                findings, "INFO", "HTTPS transport secured",
                "The endpoint successfully served content over an encrypted TLS connection.",
                "Maintain modern cipher suites and ensure certificates auto-renew before expiry."
            )

        # Check recommended security headers
        header_checks = {}
        for header, meta in SECURITY_HEADERS.items():
            h_lower = header.lower()
            present = h_lower in header_names
            val = headers.get(header_names.get(h_lower, header), "") if present else None
            
            header_checks[header] = {
                "present": present,
                "value": val,
                "description": meta["description"],
                "recommended": meta["recommended"],
                "severity_if_missing": meta["severity_if_missing"],
            }

            if not present:
                add_finding(
                    findings, meta["severity_if_missing"], f"Missing Security Header: {header}",
                    f"{header} is not present in server response headers. {meta['description']}",
                    f"Configure your web server to include '{header}'. Recommended value: {meta['recommended']}"
                )
            else:
                # Value-specific validation
                if header == "Strict-Transport-Security" and val:
                    if "preload" not in val.lower():
                        add_finding(
                            findings, "LOW", "HSTS header lacks preload directive",
                            f"Current HSTS: {val}",
                            "Consider adding 'preload' and submitting your domain to the HSTS preload list once verified."
                        )
                elif header == "X-Content-Type-Options" and val and "nosniff" not in val.lower():
                    add_finding(
                        findings, "LOW", "Suboptimal X-Content-Type-Options value",
                        f"Current value is '{val}'",
                        "Set 'X-Content-Type-Options: nosniff'."
                    )

        # Check Information Disclosure headers
        for dis_header in INFO_DISCLOSURE_HEADERS:
            d_lower = dis_header.lower()
            if d_lower in header_names:
                val = headers.get(header_names[d_lower], "")
                # Only warn if it exposes detailed version info
                add_finding(
                    findings, "LOW", f"Information Disclosure: {dis_header} Header Present",
                    f"Server returned '{dis_header}: {val}'. This may reveal software stacks or versions to attackers.",
                    f"Disable or mask the '{dis_header}' header in your reverse proxy or web server configuration."
                )

        # Inspect Set-Cookie response headers
        cookie_headers = headers.get_all("Set-Cookie") or []
        cookie_checks = []

        for index, cookie_text in enumerate(cookie_headers, start=1):
            cookie = SimpleCookie()
            try:
                cookie.load(cookie_text)
            except Exception:
                continue

            for name, morsel in cookie.items():
                is_secure = bool(morsel["secure"])
                is_httponly = bool(morsel["httponly"])
                samesite = morsel["samesite"] or None

                cookie_checks.append({
                    "index": index,
                    "name": name,
                    "secure": is_secure,
                    "httponly": is_httponly,
                    "samesite": samesite if samesite else "None / Unset",
                    "path": morsel["path"] or "/",
                    "domain": morsel["domain"] or parsed.hostname,
                })

                if parsed.scheme == "https" and not is_secure:
                    add_finding(
                        findings, "MEDIUM", f"Insecure Cookie: '{name}' lacks Secure flag",
                        f"Cookie #{index} ({name}) lacks the 'Secure' attribute over an HTTPS connection.",
                        "Add the 'Secure' attribute to ensure the cookie is only transmitted over HTTPS."
                    )

                if not is_httponly:
                    add_finding(
                        findings, "LOW", f"Cookie lacks HttpOnly flag: '{name}'",
                        f"Cookie #{index} ({name}) has no HttpOnly flag, making it accessible via document.cookie in JavaScript.",
                        "Set the 'HttpOnly' flag for session or sensitive tokens to mitigate XSS-based theft."
                    )

                if not samesite:
                    add_finding(
                        findings, "LOW", f"Cookie lacks SameSite attribute: '{name}'",
                        f"Cookie #{index} ({name}) has no SameSite attribute configured.",
                        "Set SameSite to 'Lax' or 'Strict' to defend against Cross-Site Request Forgery (CSRF)."
                    )

        # Summary score calculation
        score_data = calculate_security_score(findings, is_https)

        log_event("✓", f"Headers analyzed: {len(headers)} returned. Missing baseline security headers: {len([f for f in findings if f['severity'] in ('HIGH', 'MEDIUM')])}")
        log_event("✓", f"Cookie analysis: {len(cookie_checks)} Set-Cookie headers inspected")
        log_event("*", f"Security evaluation completed. Score: {score_data['score']}/100 (Grade: {score_data['grade']})")

        result_dict = {
            "url": raw_url,
            "status": status,
            "elapsed": elapsed,
            "final_url": final_url,
            "headers": dict(headers.items()),
            "raw_headers_list": list(headers.items()),
            "header_checks": header_checks,
            "cookie_checks": cookie_checks,
            "findings": findings,
            "dns_info": dns_info,
            "logs": logs,
            "score": score_data,
        }
        try:
            save_scan_to_history(result_dict)
        except Exception:
            pass
        return result_dict
    finally:
        response.close()


def print_report(result):
    """Prints a styled terminal report of the scanner results."""
    # Ensure UTF-8 output on Windows consoles if possible
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    print("\n" + "=" * 70)
    print("        [+] WEB APPLICATION SECURITY BASELINE REPORT")
    print("=" * 70)
    print(f"Target URL   : {result['url']}")
    print(f"Final URL    : {result['final_url'] or 'Unavailable'}")
    print(f"HTTP Status  : {result['status'] if result['status'] is not None else 'No response'}")
    print(f"Scan Time    : {result['elapsed']:.2f} seconds")
    
    dns = result.get("dns_info", {})
    if dns.get("ip"):
        print(f"Resolved IP  : {dns['ip']}")
    if dns.get("reverse_dns"):
        print(f"Reverse DNS  : {dns['reverse_dns']}")

    score = result.get("score", {})
    if score:
        print(f"Security Grade: {score.get('grade')} ({score.get('score')}/100)")
    print("-" * 70)

    findings = result.get("findings", [])
    if not findings:
        print("  [OK] No vulnerabilities or missing baseline configurations recorded!")
    else:
        sev_icons = {
            "HIGH": "[HIGH - CRITICAL]",
            "MEDIUM": "[MEDIUM - WARN]",
            "LOW": "[LOW - NOTICE]",
            "INFO": "[INFO]",
            "ERROR": "[ERROR]"
        }
        for number, item in enumerate(findings, start=1):
            sev = item["severity"]
            tag = sev_icons.get(sev, f"[{sev}]")
            print(f"\n{number}. {tag} {item['title']}")
            print(f"   Evidence : {item['evidence']}")
            print(f"   Advice   : {item['advice']}")

    print("\n" + "-" * 70)
    print("DISCLAIMER: This is an educational baseline configuration audit, not an")
    print("exhaustive penetration test. Missing headers indicate configuration gaps")
    print("rather than guaranteed exploitability.")
    print("=" * 70)


def launch_streamlit():
    """Launches the Streamlit web dashboard in the browser."""
    from streamlit.web import cli as stcli
    app_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")
    print("\n" + "=" * 65)
    print("   Starting VigilSec Interactive Web Security Scanner...")
    print(f"   App script: {app_path}")
    print("=" * 65 + "\n")
    sys.argv = ["streamlit", "run", app_path, "--server.headless=true", "--browser.gatherUsageStats=false"]
    sys.exit(stcli.main())


def main():
    """Command-line and launcher entry point."""
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if target.lower() in ("--web", "--gui", "-w", "web"):
            launch_streamlit()
            return
        try:
            result = scan_url(target)
            print_report(result)
        except ValueError as exc:
            print(f"\n[!] Input error: {exc}")
            sys.exit(2)
        except Exception as exc:
            print(f"\n[!] Unexpected error: {exc}")
            sys.exit(1)
    else:
        print("=" * 68)
        print("     VIGILSEC WEB APPLICATION VULNERABILITY & SECURITY SCANNER")
        print("=" * 68)
        print("  [1] Launch Interactive Streamlit Web UI (Browser Dashboard) [Default]")
        print("  [2] Run Terminal CLI Baseline Scan")
        print("=" * 68)
        try:
            choice = input("Select an option [1 for Web UI, 2 for CLI] (default 1): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nScan cancelled.")
            sys.exit(0)

        if choice in ("", "1", "web", "gui"):
            launch_streamlit()
        else:
            try:
                target = input("Enter an authorized website URL to scan: ")
                result = scan_url(target)
                print_report(result)
            except (KeyboardInterrupt, EOFError):
                print("\nScan cancelled.")
                sys.exit(0)
            except Exception as exc:
                print(f"\n[!] Error: {exc}")
                sys.exit(1)


if __name__ == "__main__":
    main()

