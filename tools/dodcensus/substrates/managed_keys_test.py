import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import managed_keys  # noqa: E402


class EntryModeTest(unittest.TestCase):
    def test_arm64_profile_entries_use_their_provider_mode(self) -> None:
        modes = {
            "runtime": "aws", "aws_kms": "aws", "azure_key_vault": "azure", "gcp_kms": "gcp",
            "pkcs11": "hardware", "tpm2": "hardware", "yubihsm2": "hardware",
        }
        for provider, mode in modes.items():
            for entry_id in (f"hsm_kms.{provider}", f"hsm_kms.arm64.{provider}"):
                self.assertEqual(managed_keys.State._mode(entry_id), mode, entry_id)


class HardwareWitnessVerificationTest(unittest.TestCase):
    def test_tampered_signature_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trstctl-managed-key-test-") as raw:
            root = Path(raw)
            private = root / "private.pem"
            public_der = root / "public.der"
            message = b"independent managed-key witness message"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["openssl", "pkey", "-in", str(private), "-pubout", "-outform", "DER", "-out", str(public_der)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            signature = subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", str(private)], input=message,
                check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            ).stdout
            public = public_der.read_bytes()
            self.assertTrue(managed_keys.verify_message(public, signature, message))
            tampered = bytearray(signature)
            tampered[-1] ^= 0x80
            self.assertFalse(managed_keys.verify_message(public, bytes(tampered), message))
            self.assertFalse(managed_keys.verify_message(public, signature, message + b" changed"))


if __name__ == "__main__":
    unittest.main()
