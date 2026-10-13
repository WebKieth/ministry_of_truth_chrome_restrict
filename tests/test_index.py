import base64
import json
import plistlib
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import index


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = [{
            "certificate": base64.b64encode(b"certificate").decode("ascii"),
            "constraints": {"permitted_dns_names": ["example.org", ".example.net"]},
        }]

    def test_debian(self):
        data = json.loads(index.serialize_policy("debian", self.policy))
        self.assertEqual(data, {index.POLICY_NAME: self.policy})

    def test_windows(self):
        data = index.serialize_policy("windows", self.policy)
        self.assertTrue(data.startswith(b"\xff\xfe"))
        text = data.decode("utf-16")
        self.assertIn("[HKEY_CURRENT_USER\\Software\\Policies\\Google\\Chrome]\r\n", text)
        line = text.splitlines()[-1]
        prefix = f'"{index.POLICY_NAME}"="'
        self.assertTrue(line.startswith(prefix))
        value = line[len(prefix):-1].replace('\\"', '"').replace("\\\\", "\\")
        self.assertEqual(json.loads(value), self.policy)

    def test_macos(self):
        profile = plistlib.loads(index.serialize_policy("macos", self.policy))
        preferences = profile["PayloadContent"][0]["PayloadContent"]["com.google.Chrome"]
        self.assertEqual(preferences["Forced"][0]["mcx_preference_settings"],
                         {index.POLICY_NAME: self.policy})
        self.assertEqual(profile["PayloadScope"], "User")

    def test_domains(self):
        self.assertEqual(index.normalize_domains([" Example.ORG ", "example.org", ".пример.рф"]),
                         ["example.org", ".xn--e1afmkfd.xn--p1ai"])

    def test_invalid_domains(self):
        for values in ([], [""], ["."], ["https://example.org"], ["*.example.org"],
                       ["example.org:443"], ["example.org/path"], ["127.0.0.1"],
                       ["::1"], ["-example.org"], ["a..org"], ["a" * 64 + ".org"]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                index.normalize_domains(values)

    def test_bad_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.cer"
            path.write_bytes(b"not a certificate")
            with self.assertRaises(ssl.SSLError):
                index.read_certificate(path)

    def test_reject_pem_bundle(self):
        pem = ssl.DER_cert_to_PEM_cert(b"fake")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.cer"
            path.write_text(pem + pem)
            with self.assertRaises(ValueError):
                index.read_certificate(path)

    def test_cli_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            domains_path = Path(directory) / "domains.json"
            domains_path.write_text('["example.org", ".example.net"]', encoding="utf-8")
            for target in index.OUTPUT_NAMES:
                output = Path(directory) / index.OUTPUT_NAMES[target]
                with patch.object(index, "read_certificate", return_value=b"certificate"), \
                        patch.object(index, "DOMAINS_PATH", domains_path), \
                        patch("builtins.print"):
                    index.main(["--platform", target, "--output", str(output)])
                self.assertEqual(output.read_bytes() if target != "macos" else
                                 plistlib.loads(output.read_bytes())["PayloadScope"],
                                 index.serialize_policy(target, self.policy) if target != "macos"
                                 else "User")

    def test_empty_domains_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "policy.json"
            output.write_text("existing")
            domains_path = Path(directory) / "domains.json"
            domains_path.write_text("[]", encoding="utf-8")
            with patch.object(index, "DOMAINS_PATH", domains_path), patch("sys.stderr"), \
                    self.assertRaises(SystemExit) as error:
                index.main(["--platform", "debian", "--output", str(output)])
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(output.read_text(), "existing")

    def test_read_domains(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "domains.json"
            path.write_text('[" Example.ORG ", "example.org", ".пример.рф"]',
                            encoding="utf-8-sig")
            self.assertEqual(index.read_domains(path),
                             ["example.org", ".xn--e1afmkfd.xn--p1ai"])

    def test_bad_domains_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "domains.json"
            with self.assertRaisesRegex(ValueError, "Не найден файл доменов"):
                index.read_domains(path)
            for content in ("[", "[]", '{}', '"example.org"', "null", "123",
                            '[123]', '[null]', '[true]', '[{}]', '["example.org",]'):
                path.write_text(content, encoding="utf-8")
                with self.subTest(content=content), self.assertRaises(ValueError):
                    index.read_domains(path)
            path.write_bytes(b"\xff")
            with self.assertRaisesRegex(ValueError, "Некорректный JSON"):
                index.read_domains(path)

    def test_domains_path_is_next_to_script(self):
        self.assertEqual(index.DOMAINS_PATH, Path(index.__file__).resolve().parent / "domains.json")


if __name__ == "__main__":
    unittest.main()
