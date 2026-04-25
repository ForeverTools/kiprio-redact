"""Smoke tests for kiprio-redact. Run with: python -m unittest discover."""
import json
import subprocess
import sys
import tempfile
import unittest

from kiprio_redact import ALL_TYPES, __version__, find_spans, redact


class TestSpans(unittest.TestCase):
    def test_email(self):
        spans = find_spans("contact alice@example.com please")
        self.assertEqual([s["type"] for s in spans], ["email"])
        self.assertEqual(spans[0]["raw"], "alice@example.com")

    def test_phone_uk(self):
        spans = find_spans("call +44 7700 900123 today", types=["phone"])
        self.assertEqual(len(spans), 1)
        self.assertIn("7700", spans[0]["raw"])

    def test_phone_rejects_iso_date(self):
        self.assertEqual(find_spans("on 2026-04-25 at noon", types=["phone"]), [])

    def test_card_luhn_valid(self):
        spans = find_spans("pay 4111 1111 1111 1111 now", types=["card"])
        self.assertEqual(len(spans), 1)

    def test_card_luhn_invalid_rejected(self):
        # 4111 1111 1111 1112 fails Luhn
        self.assertEqual(
            find_spans("pay 4111 1111 1111 1112 now", types=["card"]),
            [],
        )

    def test_iban_valid(self):
        # GB82 WEST 1234 5698 7654 32 — canonical sample IBAN
        spans = find_spans("send to GB82 WEST 1234 5698 7654 32", types=["iban"])
        self.assertEqual(len(spans), 1)

    def test_nino_valid(self):
        spans = find_spans("NI: AB123456C reference", types=["nino"])
        self.assertEqual(len(spans), 1)

    def test_nino_rejects_bad_prefix(self):
        self.assertEqual(find_spans("BG123456C", types=["nino"]), [])

    def test_uuid_valid(self):
        spans = find_spans("id=550e8400-e29b-41d4-a716-446655440000", types=["uuid"])
        self.assertEqual(len(spans), 1)

    def test_jwt(self):
        sample = "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U end"
        spans = find_spans(sample, types=["jwt"])
        self.assertEqual(len(spans), 1)

    def test_ipv4(self):
        spans = find_spans("from 192.168.1.1 yesterday", types=["ip"])
        self.assertEqual(len(spans), 1)

    def test_ipv4_invalid_octet(self):
        self.assertEqual(find_spans("999.999.999.999", types=["ip"]), [])

    def test_ipv6(self):
        spans = find_spans("from 2001:db8::1 yesterday", types=["ip"])
        self.assertEqual(len(spans), 1)


class TestRedact(unittest.TestCase):
    def test_default_replacement(self):
        out, found = redact("hi@example.com")
        self.assertEqual(out, "[REDACTED]")
        self.assertEqual(len(found), 1)

    def test_mask_preserves_length(self):
        out, _ = redact("hi@example.com", mask="X")
        self.assertEqual(out, "X" * len("hi@example.com"))

    def test_custom_replacement(self):
        out, _ = redact("hi@example.com", replacement="<email>")
        self.assertEqual(out, "<email>")

    def test_type_filter(self):
        text = "hi@example.com 4111 1111 1111 1111"
        out, _ = redact(text, types=["email"])
        self.assertIn("4111 1111 1111 1111", out)
        self.assertIn("[REDACTED]", out)

    def test_no_findings_returns_text_unchanged(self):
        out, found = redact("nothing sensitive here")
        self.assertEqual(out, "nothing sensitive here")
        self.assertEqual(found, [])

    def test_overlap_resolution(self):
        # An IBAN-shaped run might also match card-shaped digits — IBAN wins.
        out, found = redact("acct GB82 WEST 1234 5698 7654 32 done")
        self.assertEqual(len([f for f in found if f["type"] == "iban"]), 1)


class TestCLI(unittest.TestCase):
    """End-to-end via subprocess against the installed entry point."""

    def _run(self, args, stdin=""):
        return subprocess.run(
            [sys.executable, "-m", "kiprio_redact"] + args,
            input=stdin, capture_output=True, text=True, timeout=10,
        )

    def test_smoke_email_default(self):
        r = self._run([], stdin="contact alice@example.com")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "contact [REDACTED]")

    def test_smoke_mask(self):
        r = self._run(["-m", "X"], stdin="hi@example.com")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "X" * len("hi@example.com"))

    def test_smoke_replace(self):
        r = self._run(["-r", "<pii>"], stdin="hi@example.com")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "<pii>")

    def test_smoke_types_filter(self):
        r = self._run(["-t", "email"], stdin="hi@example.com 4111 1111 1111 1111")
        self.assertIn("[REDACTED]", r.stdout)
        self.assertIn("4111 1111 1111 1111", r.stdout)

    def test_smoke_json(self):
        r = self._run(["--json"], stdin="hi@example.com")
        self.assertEqual(r.returncode, 0)
        payload = json.loads(r.stdout)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["findings"][0]["type"], "email")

    def test_smoke_verbose_to_stderr(self):
        r = self._run(["-v"], stdin="hi@example.com 4111 1111 1111 1111")
        self.assertEqual(r.returncode, 0)
        self.assertIn("email=1", r.stderr)
        self.assertIn("card=1", r.stderr)

    def test_smoke_unknown_type_rejected(self):
        r = self._run(["-t", "ssn"], stdin="hi@example.com")
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown type", r.stderr)

    def test_smoke_file_in_out(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fin:
            fin.write("contact hi@example.com")
            inpath = fin.name
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fout:
            outpath = fout.name
        r = self._run(["-i", inpath, "-o", outpath])
        self.assertEqual(r.returncode, 0)
        self.assertEqual(open(outpath).read(), "contact [REDACTED]")


if __name__ == "__main__":
    unittest.main()
