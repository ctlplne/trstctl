import subprocess
import sys
import tempfile
import json
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

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


class AzureDeletedKeyReadbackTest(unittest.TestCase):
    def test_soft_deleted_key_has_authenticated_dates_and_active_key_absent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trstctl-azure-deleted-test-") as raw:
            state = managed_keys.State("hsm_kms.azure_key_vault", Path(raw))
            state.create_named("owned-key")
            server = managed_keys.LoopbackHTTPServer(("127.0.0.1", 0), managed_keys.handler_for(state))
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            base = f"http://127.0.0.1:{server.server_port}"

            def request(path: str, method: str = "GET", *, auth: bool = True):
                headers = {"Authorization": "Bearer " + managed_keys.AZURE_TOKEN} if auth else {}
                try:
                    with urlopen(Request(base + path, headers=headers, method=method), timeout=3) as response:
                        return response.status, json.load(response)
                except HTTPError as error:
                    with error:
                        return error.code, json.load(error)

            try:
                self.assertEqual(request("/deletedkeys/owned-key")[0], 404)
                status, active = request("/keys/owned-key")
                self.assertEqual(status, 200)
                self.assertGreater(active["attributes"]["created"], 0)
                self.assertEqual(request("/keys/owned-key", "DELETE")[0], 200)
                self.assertEqual(request("/keys/owned-key")[0], 404)
                self.assertEqual(request("/deletedkeys/owned-key", auth=False)[0], 401)
                status, deleted = request("/deletedkeys/owned-key?api-version=7.4")
                self.assertEqual(status, 200)
                self.assertEqual(deleted["recoveryId"],
                                 "https://dod.managedhsm.azure.net/deletedkeys/owned-key")
                self.assertGreater(deleted["attributes"]["created"], 0)
                self.assertEqual(deleted["attributes"]["created"], active["attributes"]["created"])
                self.assertGreater(deleted["scheduledPurgeDate"], deleted["deletedDate"])
                self.assertEqual(request("/deletedkeys/missing")[0], 404)
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=3)


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
