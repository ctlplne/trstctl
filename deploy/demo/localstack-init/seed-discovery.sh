#!/bin/sh
# Seeds the demo emulator with what the shipped cloud discovery sources look for:
# one Secrets Manager secret tagged type=certificate whose value is a PEM
# certificate, one untagged secret the tag filter must skip, and one ACM
# certificate. Runs once LocalStack is ready; safe to repeat. The private key is
# generated here and never leaves the emulator.
set -eu
REGION=us-east-1
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 90 -sha256 \
  -subj "/CN=edge-gateway.demo.trstctl.local/O=Acme Robotics Demo" \
  -addext "subjectAltName=DNS:edge-gateway.demo.trstctl.local" \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1

if ! awslocal secretsmanager describe-secret --region "$REGION" --secret-id demo/edge-gateway/tls >/dev/null 2>&1; then
  awslocal secretsmanager create-secret --region "$REGION" \
    --name demo/edge-gateway/tls \
    --description "Demo TLS certificate for the edge gateway (discovery fixture)" \
    --secret-string "file://$WORK/cert.pem" \
    --tags Key=type,Value=certificate Key=owner,Value=platform-team >/dev/null
fi
if ! awslocal secretsmanager describe-secret --region "$REGION" --secret-id demo/reporting/api-token >/dev/null 2>&1; then
  awslocal secretsmanager create-secret --region "$REGION" \
    --name demo/reporting/api-token \
    --description "Demo opaque token (not a certificate; the tag filter must skip it)" \
    --secret-string "demo-not-a-real-token" >/dev/null
fi
if [ "$(awslocal acm list-certificates --region "$REGION" --query 'length(CertificateSummaryList)' --output text)" = "0" ]; then
  awslocal acm import-certificate --region "$REGION" \
    --certificate "fileb://$WORK/cert.pem" --private-key "fileb://$WORK/key.pem" \
    --tags Key=type,Value=certificate >/dev/null
fi
echo "localstack discovery fixtures ready"
