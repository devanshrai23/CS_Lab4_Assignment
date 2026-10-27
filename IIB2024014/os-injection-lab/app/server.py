"""A deliberately vulnerable, container-only teaching lab. Never deploy publicly."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
SAMPLES = ROOT / "samples"
STATIC = ROOT / "static"
ALLOWED_FILES = ("welcome.txt", "release-notes.txt", "invoices.csv")
DEMO_PAYLOAD = "welcome.txt; printf 'OS_INJECTION_CONFIRMED\\n'"
SHA256SUM = shutil.which("sha256sum") or "/usr/bin/sha256sum"
MAX_BODY = 2048


def vulnerable_checksum(filename: str) -> dict:
    """INTENTIONAL CWE-78: input becomes shell syntax, not just a filename."""
    # VULNERABLE SINK: the semicolon in user input starts a second command.
    command = f"{SHA256SUM} -- {filename}"
    process = subprocess.Popen(
        command,
        shell=True,  # INTENTIONAL VULNERABILITY for the assignment.
        cwd=SAMPLES,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        start_new_session=True,
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LC_ALL": "C"},
    )
    try:
        stdout, stderr = process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        # Kill the whole process group, including children of /bin/sh.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        return {
            "status": "error", "stdout": "", "stderr": "Lab command timed out.",
            "returncode": None, "execution": command,
            "explanation": "The lab stops commands after two seconds.",
        }
    return {
        "status": "executed", "stdout": stdout[:8192], "stderr": stderr[:8192],
        "returncode": process.returncode, "execution": command,
        "explanation": "A shell parsed the filename and returned command output.",
    }


def secure_checksum(filename: str) -> dict:
    """FIX: compute with a native library; never construct an OS command."""
    # An exact server-side allow-list also confines access to the sample dataset.
    if filename not in ALLOWED_FILES:
        return {
            "status": "blocked", "stdout": "", "stderr": "Unknown sample filename.",
            "returncode": None, "execution": "No shell or child process created.",
            "explanation": "Only the three sample filenames are accepted. Input is never evaluated as shell syntax.",
        }
    # MITIGATED SINK: data stays data; hashlib performs the work in-process.
    digest = hashlib.sha256((SAMPLES / filename).read_bytes()).hexdigest()
    return {
        "status": "accepted", "stdout": f"{digest}  {filename}\n", "stderr": "",
        "returncode": 0, "execution": "hashlib.sha256(sample_bytes).hexdigest()",
        "explanation": "The checksum is computed by Python. There is no shell to interpret separators.",
    }


def run_checksum(mode: str, filename: str) -> dict:
    if mode not in ("vulnerable", "secure"):
        raise ValueError("Unknown mode")
    if not isinstance(filename, str) or not filename or len(filename) > 256 or "\x00" in filename:
        raise ValueError("Filename must contain 1-256 characters and no null bytes.")
    started = time.monotonic()
    result = (vulnerable_checksum if mode == "vulnerable" else secure_checksum)(filename)
    result.update(mode=mode, filename=filename, elapsed_ms=round((time.monotonic() - started) * 1000, 2))
    return result


class Handler(BaseHTTPRequestHandler):
    server_version = "ChecksumLab/1.0"
    sys_version = ""

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        super().end_headers()

    def send_bytes(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def json_response(self, status: int, data: dict):
        self.send_bytes(status, json.dumps(data, ensure_ascii=True).encode(), "application/json; charset=utf-8")

    def valid_host(self) -> bool:
        # A local browser may use localhost or a loopback IP. Reject rebinding hosts.
        host = self.headers.get("Host", "")
        try:
            parsed = urlsplit("http://" + host)
            if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
                return False
            if parsed.port is None:
                return False
            return parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback
        except (ValueError, TypeError):
            return False

    def do_GET(self):
        if not self.valid_host():
            return self.json_response(403, {"error": "Use the localhost lab address."})
        path = urlsplit(self.path).path
        if path == "/api/health":
            return self.json_response(200, {"status": "ok", "variant": "in-band", "files": list(ALLOWED_FILES), "payload": DEMO_PAYLOAD})
        routes = {"/": ("index.html", "text/html; charset=utf-8"),
                  "/style.css": ("style.css", "text/css; charset=utf-8"),
                  "/app.js": ("app.js", "text/javascript; charset=utf-8")}
        if path not in routes:
            return self.json_response(404, {"error": "Not found"})
        name, kind = routes[path]
        self.send_bytes(200, (STATIC / name).read_bytes(), kind)

    def do_POST(self):
        if not self.valid_host():
            return self.json_response(403, {"error": "Use the localhost lab address."})
        origin = self.headers.get("Origin")
        if (origin and origin != "http://" + self.headers["Host"]) or self.headers.get("Sec-Fetch-Site") == "cross-site":
            return self.json_response(403, {"error": "Cross-origin requests are disabled."})
        if self.headers.get("X-Lab-Request") != "1":
            return self.json_response(403, {"error": "Missing X-Lab-Request: 1 header."})
        path = urlsplit(self.path).path
        modes = {"/api/vulnerable": "vulnerable", "/api/secure": "secure"}
        if path not in modes:
            return self.json_response(404, {"error": "Unknown endpoint"})
        if self.headers.get("Transfer-Encoding"):
            return self.json_response(400, {"error": "Transfer-Encoding is not supported."})
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            return self.json_response(415, {"error": "Send application/json."})
        try:
            size = int(self.headers.get("Content-Length", "-1"))
            if not 0 < size <= MAX_BODY:
                return self.json_response(413, {"error": "Body must contain 1-2048 bytes."})
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError("JSON body must be an object.")
            result = run_checksum(modes[path], data.get("filename"))
        except (ValueError, UnicodeError) as error:
            return self.json_response(400, {"error": str(error)})
        except OSError:
            return self.json_response(500, {"error": "The lab could not read a sample or start its command."})
        self.json_response(422 if result["status"] == "blocked" else 200, result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if os.environ.get("OS_INJECTION_LAB_CONTAINER") != "1" or not Path("/.dockerenv").exists():
        parser.error("Run with Docker Compose; this lab intentionally executes injected commands.")
    if os.geteuid() == 0:
        parser.error("Run the container as its configured non-root user.")
    server = HTTPServer(("0.0.0.0", args.port), Handler)
    server.timeout = 3
    print(f"Checksum Lab listening on container port {args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
