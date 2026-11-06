#!/usr/bin/env bash
# Native IAM capture and approved change proof. LocalStack does not prove AWS enforcement.
set -euo pipefail
umask 077
repo=$(cd "$(dirname "$0")/../.." && pwd)
image='localstack/localstack@sha256:b279c01f4cfb8f985a482e4014cabc1e2697b9d7a6c8c8db2e40f4d9f93687c7'
docker image inspect "$image" >/dev/null
proof=$(mktemp -d "${TMPDIR:-/tmp}/trstctl-cloud-entitlements.XXXXXX")
id=$(docker run --pull never --detach --network "${TRSTCTL_LAB_NETWORK:-bridge}" -p 127.0.0.1::4566 -e SERVICES=iam,sts,s3 "$image")
printf '%s\n' "$id" > "$proof/container.id"
trap 'docker stop "$id" > "$proof/stop.log" 2>&1 || true' EXIT
for attempt in $(seq 1 60); do
  if docker exec "$id" awslocal sts get-caller-identity >/dev/null 2>&1; then break; fi
  if [ "$attempt" = 60 ]; then echo 'Owned LocalStack did not become ready' >&2; exit 1; fi
  sleep 1
done
endpoint="http://$(docker port "$id" 4566/tcp)"
aws_native(){ docker exec "$id" awslocal "$@"; }
trust='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
read_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::a264-workload/note"}]}'
aws_native iam create-user --user-name a264-workload >/dev/null
aws_native iam create-role --role-name a264-reader --assume-role-policy-document "$trust" >/dev/null
trust_replacement='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}]}'
aws_native iam create-role --role-name a264-replacement553 --assume-role-policy-document "$trust_replacement" >/dev/null
aws_native iam put-role-policy --role-name a264-replacement553 --policy-name read-note --policy-document "$read_policy" >/dev/null
aws_native iam put-user-policy --user-name a264-workload --policy-name direct --policy-document "$read_policy" >/dev/null
aws_native iam create-policy --policy-name a264-boundary --policy-document "$read_policy" >/dev/null
aws_native iam put-user-permissions-boundary --user-name a264-workload --permissions-boundary arn:aws:iam::000000000000:policy/a264-boundary >/dev/null
aws_native iam create-group --group-name a264-machines >/dev/null
aws_native iam put-group-policy --group-name a264-machines --policy-name group-read --policy-document "$read_policy" >/dev/null
aws_native iam add-user-to-group --user-name a264-workload --group-name a264-machines >/dev/null
aws_native iam create-access-key --user-name a264-workload >/dev/null
aws_native iam create-user --user-name a264-change552 >/dev/null
aws_native iam create-access-key --user-name a264-change552 >/dev/null
change_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::a264-workload/note","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}},{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::a264-workload/note"}]}'
aws_native iam put-user-policy --user-name a264-change552 --policy-name baseline --policy-document "$change_policy" >/dev/null
aws_native sts get-session-token --duration-seconds 3600 > "$proof/session.json"
aws_native --version > "$proof/client-version.txt" 2>&1
(cd "$repo" && TRSTCTL_A264_IAM_ENDPOINT="$endpoint" TRSTCTL_A264_IAM_SESSION_FILE="$proof/session.json" go test ./internal/cloudentitlements/awsiam -run '^TestAWSIAMNativeInventoryA264$' -count=1 -v) | tee "$proof/native.log"
(cd "$repo" && TRSTCTL_A264_IAM_ENDPOINT="$endpoint" TRSTCTL_A264_IAM_SESSION_FILE="$proof/session.json" go test ./internal/server -run '^TestServed(CloudMachineEntitlementCapture|ApprovedCloudKeyRevocation|CloudReplacementSTSIdentityProof)A264$' -count=1 -v) | tee "$proof/served.log"
printf 'Native IAM metadata and served assessment proof retained at %s\n' "$proof"
