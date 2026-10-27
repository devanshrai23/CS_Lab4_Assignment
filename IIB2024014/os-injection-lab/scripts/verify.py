"""Reproduce the baseline, exploit, and blocked attempt against THIS localhost lab."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import urllib.error
import urllib.request
from urllib.parse import urlsplit

PAYLOAD = "welcome.txt; printf 'OS_INJECTION_CONFIRMED\\n'"
ROOT = Path(__file__).resolve().parents[1]


def post(base, route, filename):
    body = json.dumps({"filename": filename}).encode()
    request = urllib.request.Request(base + route, data=body, method="POST", headers={
        "Content-Type": "application/json", "X-Lab-Request": "1"})
    try:
        response = urllib.request.urlopen(request, timeout=8)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return {"request": {"method": "POST", "path": route, "headers": {
            "Content-Type": "application/json", "X-Lab-Request": "1"}, "body": {"filename": filename}},
            "http_status": response.code, "response": json.load(response)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "evidence")
    args = parser.parse_args()
    url = urlsplit(args.base_url)
    if url.scheme != "http" or url.hostname not in ("127.0.0.1", "localhost") or url.path not in ("", "/") or url.username or url.password or url.query or url.fragment:
        parser.error("Use only this lab's http://127.0.0.1:PORT address.")
    base = args.base_url.rstrip("/")
    records = [post(base, "/api/vulnerable", "welcome.txt"), post(base, "/api/secure", "welcome.txt"),
               post(base, "/api/vulnerable", PAYLOAD), post(base, "/api/secure", PAYLOAD)]
    a, b, c, d = records
    checks = {"baseline_http_200": a["http_status"] == b["http_status"] == 200,
              "baseline_digest_equal": a["response"]["stdout"] == b["response"]["stdout"],
              "exploit_http_200": c["http_status"] == 200,
              "exploit_marker_returned": c["response"]["stdout"].splitlines()[-1] == "OS_INJECTION_CONFIRMED",
              "identical_payload": c["request"]["body"] == d["request"]["body"],
              "mitigation_http_422": d["http_status"] == 422,
              "mitigation_blocks_output": d["response"]["status"] == "blocked" and d["response"]["stdout"] == ""}
    files = ["app/server.py", "app/static/index.html", "app/static/app.js", "app/static/style.css", "Dockerfile", "compose.yaml", "tests/test_lab.py"]
    report = {"captured_at_utc": datetime.now(timezone.utc).isoformat(), "base_url": base,
              "variant": "In-band OS command injection", "payload": PAYLOAD, "checks": checks,
              "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in files}, "requests": records}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "requests.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = ["CHECKSUM LAB - REPRODUCIBLE HTTP EVIDENCE", f"Captured: {report['captured_at_utc']}", f"Payload: {PAYLOAD}", ""]
    for record in records:
        lines.extend([f"POST {record['request']['path']}", "Content-Type: application/json", "X-Lab-Request: 1",
                      json.dumps(record["request"]["body"]), f"HTTP {record['http_status']}",
                      json.dumps(record["response"], indent=2), ""])
    lines.extend(f"{'PASS' if passed else 'FAIL'}  {name}" for name, passed in checks.items())
    (args.output_dir / "transcript.txt").write_text("\n".join(lines) + "\n")
    for name, passed in checks.items():
        print(f"{'PASS' if passed else 'FAIL'}  {name}")
    if not all(checks.values()):
        raise SystemExit(1)
    print(f"Evidence written to {args.output_dir}")


if __name__ == "__main__":
    main()
