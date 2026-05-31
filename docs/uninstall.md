# Uninstall

certctl is designed to leave cleanly. Removing it never touches the credentials
it manages on your hosts — those certificates and keys stay where they were
deployed. Uninstalling only removes the certctl binaries, services, and (if you
choose) its datastore.

Pick your platform.

## Docker

If you used the evaluation stack, tear it down. To keep the data, omit
`--volumes`:

```bash
docker compose -f deploy/docker/docker-compose.yml down            # stop, keep data
docker compose -f deploy/docker/docker-compose.yml down --volumes  # also delete Postgres/NATS data
```

For a standalone container, stop and remove it, then drop the image:

```bash
docker rm -f certctl
docker image rm ghcr.io/imfeelingtheagi/certctl:latest
```

## Kubernetes

Delete the agent DaemonSet and its supporting objects (deleting the namespace
removes everything in it):

```bash
kubectl delete -f deploy/kubernetes/daemonset.yaml
kubectl delete -f deploy/kubernetes/rbac.yaml
kubectl delete -f deploy/kubernetes/namespace.yaml
```

## Linux

Stop and disable the service, then remove the binaries:

```bash
sudo systemctl disable --now certctl-agent
sudo rm -f /etc/systemd/system/certctl-agent.service
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/certctl /usr/local/bin/certctl-agent /usr/local/bin/certctl-signer
```

Optionally remove the agent's local state directory (its data dir and the
telemetry instance ID, if you enabled telemetry).

## macOS

Unload the `launchd` job and remove the binary:

```bash
sudo launchctl unload /Library/LaunchDaemons/io.certctl.agent.plist
sudo rm -f /Library/LaunchDaemons/io.certctl.agent.plist
sudo rm -f /usr/local/bin/certctl-agent
```

Certificates the agent placed in the keychain remain until you remove them.

## Windows

Uninstall the MSI, which stops and unregisters the SCM service:

```powershell
msiexec /x certctl-agent.msi /qn
```

Or remove **certctl agent** from *Settings → Apps*. Certificates already in the
Windows certificate store are left in place.

## Remove the datastore (optional)

certctl's own state lives entirely in PostgreSQL and NATS JetStream. If you ran
external datastores and want certctl gone completely, drop its database and
JetStream streams on those servers. With the bundled Compose datastores, the
`down --volumes` command above already removed them.
