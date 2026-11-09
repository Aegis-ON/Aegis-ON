import unittest

from aegis_on.privacy import redact_for_display, redact_text


class PrivacyRegressionTests(unittest.TestCase):
    def test_ipv6_addresses_are_pseudonymized_in_common_contexts(self):
        samples = (
            ("host 2001:db8::1 connected", "2001:db8::1"),
            ("host 2001:0db8:0000:0000:0000:0000:0000:0001", "2001:0db8:0000:0000:0000:0000:0000:0001"),
            ("connect https://[2001:db8::1]:8443/path", "2001:db8::1"),
            ("connect [::1]:443", "::1"),
            ("mapped ::ffff:192.0.2.1 connected", "::ffff:192.0.2.1"),
            ("link-local fe80::1%en0.", "fe80::1%en0"),
            ("unspecified ::.", "::"),
        )
        for text, address in samples:
            with self.subTest(address=address):
                result = redact_text(text)
                self.assertNotIn(address, result)
                self.assertIn("[IP:", result)

        self.assertRegex(redact_text("connect https://[2001:db8::1]:8443/path"), r"^connect https://\[\[IP:[0-9a-f]{10}\]\]:8443/path$")
        self.assertRegex(redact_text("mapped ::ffff:192.0.2.1 connected"), r"^mapped \[IP:[0-9a-f]{10}\] connected$")
        self.assertEqual(redact_text("2001:db8::1"), redact_text("2001:0db8:0000:0000:0000:0000:0000:0001"))

    def test_invalid_ipv6_candidates_are_left_unchanged(self):
        text = "time 12:34:56 and invalid 2001:db8:1:2:3:4:5:6:7"
        self.assertEqual(redact_text(text), text)

    def test_existing_pseudonymization_and_nested_values(self):
        result = redact_for_display({"values": ["analyst@example.org", "010-1234-5678", "10.20.30.40", "2001:db8::2"]})
        self.assertEqual([value.split(":", 1)[0] for value in result["values"]], ["[EMAIL", "[PHONE", "[IP", "[IP"])

    def test_ipv6_after_colon_separated_labels(self):
        for label, address in (("host", "2001:db8::1"), ("source", "fe80::1%en0"),
                               ("client.ip", "2001:db8::1"), ("source.ip", "fe80::1%en0")):
            with self.subTest(label=label):
                result = redact_text(f"{label}:{address}")
                self.assertTrue(result.startswith(f"{label}:[IP:"))
                self.assertNotIn(address, result)

    def test_ipv6_label_support_preserves_normal_text(self):
        text = "host:available time:12:34:56 and invalid dead:db8:1:2:3:4:5:6:7"
        self.assertEqual(redact_text(text), text)


if __name__ == "__main__":
    unittest.main()
