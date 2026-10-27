"""Behavioral regressions: actual exploitation, preserved behavior, and no spawn in the fix."""
import hashlib
from http.client import HTTPConnection
import json
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import server


class ChecksumTests(unittest.TestCase):
    def test_normal_filenames_keep_the_same_behavior(self):
        for filename in server.ALLOWED_FILES:
            with self.subTest(filename=filename):
                before = server.run_checksum("vulnerable", filename)
                after = server.run_checksum("secure", filename)
                expected = hashlib.sha256((server.SAMPLES / filename).read_bytes()).hexdigest()
                self.assertEqual(before["returncode"], 0)
                self.assertEqual(before["stdout"], after["stdout"])
                self.assertTrue(after["stdout"].startswith(expected))

    def test_in_band_exploit_executes_second_command(self):
        result = server.run_checksum("vulnerable", server.DEMO_PAYLOAD)
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["stdout"].splitlines()[-1], "OS_INJECTION_CONFIRMED")
        self.assertIn("welcome.txt", result["stdout"])

    def test_identical_exploit_is_blocked_without_starting_process(self):
        with patch.object(server.subprocess, "Popen", side_effect=AssertionError("Secure route started a process")):
            result = server.run_checksum("secure", server.DEMO_PAYLOAD)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["stdout"], "")

    def test_valid_secure_request_also_never_starts_a_process(self):
        with patch.object(server.subprocess, "Popen", side_effect=AssertionError("Secure route started a process")):
            self.assertEqual(server.run_checksum("secure", "welcome.txt")["status"], "accepted")

    def test_alternative_shell_syntax_and_paths_are_rejected(self):
        values = ["welcome.txt && printf MARKER", "welcome.txt | printf MARKER",
                  "$(printf MARKER)", "welcome.txt\nprintf MARKER", "../server.py",
                  "/etc/passwd", "--help", "missing.txt", "WELCOME.TXT"]
        with patch.object(server.subprocess, "Popen", side_effect=AssertionError("Unexpected spawn")):
            for filename in values:
                with self.subTest(filename=filename):
                    self.assertEqual(server.run_checksum("secure", filename)["status"], "blocked")

    def test_bad_input_types_and_lengths_are_rejected(self):
        for value in [None, 23, [], {}, "", "x" * 257, "welcome.txt\x00"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                server.run_checksum("secure", value)

    def test_long_running_injected_command_times_out(self):
        started = time.monotonic()
        result = server.run_checksum("vulnerable", "welcome.txt; sleep 5")
        self.assertEqual(result["status"], "error")
        self.assertLess(time.monotonic() - started, 4)
        self.assertIn("timed out", result["stderr"])


class QuietHandler(server.Handler):
    def log_message(self, *args):
        pass


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server.HTTPServer(("127.0.0.1", 0), QuietHandler)
        cls.port = cls.httpd.server_port
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def request(self, path, data=None, headers=None, method="POST"):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        defaults = {"Content-Type": "application/json", "X-Lab-Request": "1"}
        defaults.update(headers or {})
        connection.request(method, path, body=json.dumps(data).encode() if data is not None else None, headers=defaults)
        response = connection.getresponse()
        status, body, response_headers = response.status, response.read(), dict(response.getheaders())
        connection.close()
        return status, body, response_headers

    def test_real_http_exploit_and_fix_use_identical_body(self):
        body = {"filename": server.DEMO_PAYLOAD}
        status_before, before, _ = self.request("/api/vulnerable", body)
        status_after, after, _ = self.request("/api/secure", body)
        self.assertEqual(status_before, 200)
        self.assertIn("OS_INJECTION_CONFIRMED", json.loads(before)["stdout"])
        self.assertEqual(status_after, 422)
        self.assertEqual(json.loads(after)["stdout"], "")

    def test_cross_origin_cannot_reach_vulnerable_sink(self):
        with patch.object(server.subprocess, "Popen", side_effect=AssertionError("Unexpected spawn")):
            status, _, _ = self.request("/api/vulnerable", {"filename": server.DEMO_PAYLOAD}, {"Origin": "https://example.invalid"})
        self.assertEqual(status, 403)

    def test_rebinding_host_is_rejected(self):
        self.assertEqual(self.request("/api/health", headers={"Host": "example.invalid:8080"}, method="GET")[0], 403)

    def test_plain_form_request_cannot_execute_commands(self):
        self.assertEqual(self.request("/api/vulnerable", {"filename": "welcome.txt"}, {"X-Lab-Request": ""})[0], 403)

    def test_non_object_json_is_rejected(self):
        self.assertEqual(self.request("/api/secure", ["welcome.txt"])[0], 400)

    def test_static_files_are_explicit_and_have_security_headers(self):
        status, body, headers = self.request("/", method="GET")
        self.assertEqual(status, 200)
        self.assertIn(b"Checksum Lab", body)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(self.request("/../server.py", method="GET")[0], 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
