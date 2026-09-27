# Public timestamp fixture

This owned ECDSA timestamp fixture contains only a public TSA certificate,
a signature and a message imprint. Its ephemeral private keys were destroyed;
no private key is needed to run the verifier or fuzz target.

OpenSSL 3.6.2 independently verified the CMS signature, certificate chain and
message imprint. It decoded the CMS time as 2026-09-26T23:33:20Z and nonce 739.
The separately authenticated manifest time is 2026-09-26T23:33:20.123456789Z.
This preserves the historical encoder's exact whole-second precision mapping.
It is not evidence of revocation checks or a served TSA deployment.
