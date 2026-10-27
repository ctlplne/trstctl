import argparse
import binascii

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from kmip.core import enums
from kmip.pie.client import ProxyKmipClient
from kmip.pie.exceptions import KmipOperationFailure


def connect(args):
    return ProxyKmipClient(
        hostname=args.host,
        port=args.port,
        cert=args.cert,
        key=args.key,
        ca=args.ca,
        config=None,
    )


def refused(operation):
    try:
        operation()
    except KmipOperationFailure as failure:
        return failure.reason
    raise SystemExit("an operation the server should refuse succeeded")


def state(client, uid):
    _, attributes = client.get_attributes(uid, ["State"])
    if len(attributes) != 1:
        raise SystemExit(f"State of {uid}: {attributes}")
    return attributes[0].attribute_value.value


def aes(args):
    with connect(args) as client:
        uid = client.create(enums.CryptographicAlgorithm.AES, 256)
        key = client.get(uid)
    if key.cryptographic_algorithm != enums.CryptographicAlgorithm.AES or len(key.value) != 32:
        raise SystemExit(f"unexpected AES key: {key.cryptographic_algorithm} {len(key.value)}")
    print(f"PYKMIP_AES_OK uid={uid} value={binascii.hexlify(key.value[:4]).decode()}...")


def keypair(args):
    data = b"the release manifest"
    pss = {
        "cryptographic_algorithm": enums.CryptographicAlgorithm.RSA,
        "hashing_algorithm": enums.HashingAlgorithm.SHA_256,
        "padding_method": enums.PaddingMethod.PSS,
    }
    with connect(args) as client:
        public_uid, private_uid = client.create_key_pair(
            enums.CryptographicAlgorithm.RSA,
            2048,
            public_name="release-verify",
            public_usage_mask=[enums.CryptographicUsageMask.VERIFY],
            private_name="release-sign",
            private_usage_mask=[enums.CryptographicUsageMask.SIGN],
        )
        if state(client, private_uid) != enums.State.PRE_ACTIVE:
            raise SystemExit("a new private key is not Pre-Active")
        reason = refused(lambda: client.sign(data, uid=private_uid, cryptographic_parameters=pss))
        if reason != enums.ResultReason.PERMISSION_DENIED:
            raise SystemExit(f"signing with a Pre-Active key: {reason}")

        client.activate(private_uid)
        client.activate(public_uid)
        if state(client, private_uid) != enums.State.ACTIVE:
            raise SystemExit("Activate did not make the private key Active")
        signature = client.sign(data, uid=private_uid, cryptographic_parameters=pss)
        if client.signature_verify(data, signature, uid=public_uid, cryptographic_parameters=pss) != enums.ValidityIndicator.VALID:
            raise SystemExit("the server did not verify its own signature")
        if client.signature_verify(b"tampered", signature, uid=public_uid, cryptographic_parameters=pss) != enums.ValidityIndicator.INVALID:
            raise SystemExit("the server verified a signature over a tampered message")

        public = client.get(public_uid)
        verifier = serialization.load_der_public_key(public.value)
        verifier.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
        reason = refused(lambda: client.get(private_uid))
        if reason != enums.ResultReason.NOT_EXTRACTABLE:
            raise SystemExit(f"Get of the private key: {reason}")
        names = client.get_attribute_list(private_uid)
        for want in ("Name", "State", "Link", "Cryptographic Usage Mask"):
            if want not in names:
                raise SystemExit(f"attribute list {names} has no {want}")

        ec_public, ec_private = client.create_key_pair(enums.CryptographicAlgorithm.ECDSA, 256)
        client.activate(ec_private)
        client.activate(ec_public)
        ecdsa = {"digital_signature_algorithm": enums.DigitalSignatureAlgorithm.ECDSA_WITH_SHA256}
        ec_signature = client.sign(data, uid=ec_private, cryptographic_parameters=ecdsa)
        if client.signature_verify(data, ec_signature, uid=ec_public, cryptographic_parameters=ecdsa) != enums.ValidityIndicator.VALID:
            raise SystemExit("the ECDSA signature did not verify")
        serialization.load_der_public_key(client.get(ec_public).value).verify(ec_signature, data, ec.ECDSA(hashes.SHA256()))

        client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, uid=private_uid)
        if state(client, private_uid) != enums.State.COMPROMISED:
            raise SystemExit("a compromise revocation did not leave the key Compromised")
        reason = refused(lambda: client.sign(data, uid=private_uid, cryptographic_parameters=pss))
        if reason != enums.ResultReason.PERMISSION_DENIED:
            raise SystemExit(f"signing with a compromised key: {reason}")
    print(f"PYKMIP_KEYPAIR_OK private={private_uid} public={public_uid} ecdsa={ec_private}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("flow", choices=["aes", "keypair"])
    args = parser.parse_args()
    {"aes": aes, "keypair": keypair}[args.flow](args)


if __name__ == "__main__":
    main()
