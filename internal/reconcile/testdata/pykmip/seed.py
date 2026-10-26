"""Seed the PyKMIP server with the objects the KMIP reconciliation proof observes.

Run inside the test container after the server is up. It creates two AES keys
(activating one), registers one X.509 certificate from /pki/observed-ca.der,
and prints the identifiers it made, one per line, for the test to compare.
"""
from kmip.core import enums
from kmip.pie import client, objects

with open("/pki/observed-ca.der", "rb") as f:
    certificate_der = f.read()

c = client.ProxyKmipClient(
    hostname="127.0.0.1",
    port=5696,
    cert="/pki/client.pem",
    key="/pki/client-key.pem",
    ca="/pki/ca.pem",
)
with c:
    active = c.create(enums.CryptographicAlgorithm.AES, 256)
    c.activate(active)
    pending = c.create(enums.CryptographicAlgorithm.AES, 128)
    cert = c.register(objects.X509Certificate(certificate_der))
    for uid in (active, pending, cert):
        print(uid)
