#!/usr/bin/env python3
"""
VigilSec Cyber Security Scanner - Backend HTTP Server
Serves the modern cyber frontend and exposes REST API endpoints for scanning,
history tracking, and real-time security statistics.
Uses Python's standard library ThreadingHTTPServer - zero extra dependencies required!
"""

import sys
import os
import json
import time
import socket
import urllib.parse
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# Ensure project root is in sys.path
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

# Fix Windows console charmap encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from webvulnscanner import scan_url, load_history, calculate_stats, HISTORY_FILE

PORT = 5000
HOST = "127.0.0.1"


def save_history(history):
    """Save scan history to JSON file."""
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"[!] Error saving history: {e}")


class VigilSecHTTPRequestHandler(SimpleHTTPRequestHandler):
    """Custom HTTP request handler with REST API and static file support."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PROJECT_DIR, **kwargs)

    def end_headers(self):
        """Append CORS and cache control headers."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

    def do_OPTIONS(self):
        """Handle preflight CORS requests."""
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        """Handle GET requests for static files or API endpoints."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/stats":
            self.handle_api_stats()
            return
        elif path == "/api/history":
            self.handle_api_history()
            return
        elif path == "/health":
            self.send_json_response(200, {"status": "ok", "app": "VigilSec"})
            return

        # Serve static file or fallback to index.html
        if path in ("/", ""):
            self.path = "/index.html"

        super().do_GET()

    def do_POST(self):
        """Handle POST requests for scanning."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/scan":
            self.handle_api_scan()
            return

        self.send_json_response(404, {"error": "Endpoint not found"})

    def do_DELETE(self):
        """Handle DELETE requests (e.g., clearing history)."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/history":
            save_history([])
            self.send_json_response(200, {"success": True, "message": "Scan history cleared"})
            return

        self.send_json_response(404, {"error": "Endpoint not found"})

    def send_json_response(self, status_code, data):
        """Helper to send JSON response."""
        response_bytes = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def handle_api_stats(self):
        """Return cumulative scanner statistics."""
        history = load_history()
        stats = calculate_stats(history)
        self.send_json_response(200, stats)

    def handle_api_history(self):
        """Return full scan history."""
        history = load_history()
        self.send_json_response(200, history)

    def handle_api_scan(self):
        """Execute web security scan and return results."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            payload = json.loads(body.decode("utf-8")) if body else {}

            target_url = payload.get("url", "").strip()
            timeout = int(payload.get("timeout", 8))
            enable_reverse_dns = bool(payload.get("enable_reverse_dns", True))
            max_threads = int(payload.get("max_threads", 10))

            if not target_url:
                self.send_json_response(400, {"success": False, "error": "Target URL is required"})
                return

            # Execute passive security scan
            scan_result = scan_url(
                target_url,
                timeout=timeout,
                enable_reverse_dns=enable_reverse_dns,
                max_threads=max_threads
            )

            # Record into scan history
            history = load_history()
            history_record = {
                "id": f"scan_{int(time.time() * 1000)}",
                "timestamp": int(time.time()),
                "url": scan_result.get("url"),
                "final_url": scan_result.get("final_url"),
                "status": scan_result.get("status"),
                "elapsed": scan_result.get("elapsed"),
                "score": scan_result.get("score"),
                "findings_count": len(scan_result.get("findings", [])),
                "high_count": sum(1 for f in scan_result.get("findings", []) if f["severity"] == "HIGH"),
                "header_checks_count": len(scan_result.get("header_checks", {})),
                "cookie_checks_count": len(scan_result.get("cookie_checks", [])),
            }
            # Prepend to history, keep last 50
            history.insert(0, history_record)
            if len(history) > 50:
                history = history[:50]
            save_history(history)

            # Return scan results and updated aggregate stats
            stats = calculate_stats(history)
            self.send_json_response(200, {
                "success": True,
                "result": scan_result,
                "stats": stats
            })

        except ValueError as ve:
            self.send_json_response(400, {"success": False, "error": str(ve)})
        except Exception as e:
            self.send_json_response(500, {"success": False, "error": f"Scan failed: {str(e)}"})


def find_free_port(start_port=5000, max_attempts=10):
    """Find an available port starting from start_port."""
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex((HOST, port)) != 0:
                return port
    return start_port


def run_server(port=PORT, auto_open=True):
    """Run the multi-threaded HTTP server."""
    actual_port = find_free_port(port)
    server_address = (HOST, actual_port)

    # Allow address reuse
    ThreadingHTTPServer.allow_reuse_address = True
    httpd = ThreadingHTTPServer(server_address, VigilSecHTTPRequestHandler)

    url = f"http://{HOST}:{actual_port}"
    print("=" * 64)
    print("    🛡️  VIGILSEC CYBER SECURITY WEB SCANNER  🛡️")
    print("=" * 64)
    print(f" [*] Cyber HUD Server active at: {url}")
    print(f" [*] REST API Endpoints:")
    print(f"     - POST {url}/api/scan")
    print(f"     - GET  {url}/api/stats")
    print(f"     - GET  {url}/api/history")
    print(f" [*] Press CTRL+C to terminate server")
    print("=" * 64)

    if auto_open:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] VigilSec Server shutting down gracefully.")
        httpd.server_close()


if __name__ == "__main__":
    auto_open = "--no-browser" not in sys.argv
    run_server(auto_open=auto_open)
