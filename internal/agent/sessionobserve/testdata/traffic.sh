#!/bin/sh
# SPDX-License-Identifier: BUSL-1.1
#
# X5 proof traffic: stock OpenSSL 3 servers and clients and curl on loopback,
# run from copies named x5-openssl and x5-curl in $X5_WORK, so the proof can
# tell its own sessions from any other process the probes see. Application
# data markers that must never reach the observer: x5-client-app-data,
# x5-server-app-data, x5-secret-path and x5-header-secret.
#
# It writes the certificates' SHA-256 fingerprints (fp-server, fp-client,
# fp-rsa) and the hybrid group this OpenSSL negotiates (expect-group:
# X25519MLKEM768 where OpenSSL has ML-KEM, x25519 before 3.5).
set -eu
cd "$X5_WORK"
ossl="$X5_WORK/x5-openssl"
curlbin="$X5_WORK/x5-curl"
cp "$(command -v openssl)" "$ossl"
cp "$(command -v curl)" "$curlbin"
if "$ossl" list -kem-algorithms 2>/dev/null | grep -qi mlkem768; then hybrid=X25519MLKEM768; else hybrid=x25519; fi
echo "$hybrid" > expect-group

quiet() { "$@" >/dev/null 2>&1; }
quiet "$ossl" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -subj /CN=x5-proof-ca -days 1
quiet "$ossl" req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout server.key -out server.csr -subj /CN=x5.proof.test \
  -addext subjectAltName=DNS:x5.proof.test
quiet "$ossl" x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 1 -copy_extensions copy
quiet "$ossl" req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout client.key -out client.csr -subj /CN=x5-proof-client
quiet "$ossl" x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 1
quiet "$ossl" req -x509 -newkey rsa:2048 -nodes -keyout rsa.key -out rsa.crt -subj /CN=tls12.proof.test -days 1
for c in server client rsa; do "$ossl" x509 -in "$c.crt" -noout -fingerprint -sha256 > "fp-$c"; done

# TLS 1.3 with the hybrid group and mutual TLS; the server sends a marker.
(sleep 1; echo x5-server-app-data; sleep 3) | timeout 20 "$ossl" s_server -accept 4513 -cert server.crt -key server.key \
  -CAfile ca.crt -Verify 1 -verify_return_error -tls1_3 -groups "$hybrid" -naccept 1 > s13.out 2>&1 &
# TLS 1.3 for curl.
timeout 20 "$ossl" s_server -accept 4514 -cert server.crt -key server.key -tls1_3 -www -naccept 1 > www.out 2>&1 &
# TLS 1.2 with an RSA certificate. (An echo server stops at the end of its
# input, so each one's input stays open until its client is done.)
(sleep 9) | timeout 20 "$ossl" s_server -accept 4512 -cert rsa.crt -key rsa.key -tls1_2 -naccept 1 > s12.out 2>&1 &
# TLS 1.3 where the server takes only P-256: a HelloRetryRequest.
(sleep 9) | timeout 20 "$ossl" s_server -accept 4515 -cert server.crt -key server.key -tls1_3 -groups P-256 -naccept 1 > hrr.out 2>&1 &
sleep 1

# The clients' exit status reflects how the one-shot servers close; the checks
# at the end show the handshakes and the application data went through.
(echo x5-client-app-data; sleep 3) | timeout 15 "$ossl" s_client -connect 127.0.0.1:4513 -servername x5.proof.test \
  -CAfile ca.crt -cert client.crt -key client.key -tls1_3 -groups "$hybrid" -verify_return_error > c13.out 2>&1 || true
timeout 15 "$curlbin" -s --cacert ca.crt --resolve x5.proof.test:4514:127.0.0.1 -H 'X-X5: x5-header-secret' \
  https://x5.proof.test:4514/x5-secret-path -o curl.out || true
(echo x5-client-app-data; sleep 1) | timeout 15 "$ossl" s_client -connect 127.0.0.1:4512 -servername tls12.proof.test \
  -tls1_2 > c12.out 2>&1 || true
(echo x5-client-app-data; sleep 1) | timeout 15 "$ossl" s_client -connect 127.0.0.1:4515 -servername x5.proof.test \
  -CAfile ca.crt -tls1_3 -groups "$hybrid:P-256" > chrr.out 2>&1 || true
wait
grep -q x5-server-app-data c13.out
grep -q x5-client-app-data s13.out
grep -qi 's_server' curl.out
grep -q 'Protocol *: *TLSv1.2' c12.out
grep -q x5-client-app-data hrr.out
