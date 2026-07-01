# Uninstall

trstctl is designed to leave cleanly. Removing it never touches the credentials
it manages on your hosts — those certificates and keys stay where they were
deployed. Uninstalling only removes the trstctl binaries, services, and (if you
choose) its datastore.

Pick your platform.

## Docker

If you used the blank evaluation stack, tear it down. To keep the data, omit
`--volumes`:

```bash
docker compose -f deploy/docker/docker-compose.yml down            # stop, keep data
docker compose -f deploy/docker/docker-compose.yml down --volumes  # also delete Postgres/NATS data
```

If you used the live-demo stack, use its separate compose file and volumes:

```bash
docker compose -f deploy/demo/docker-compose.yml down            # stop, keep demo data
docker compose -f deploy/demo/docker-compose.yml down --volumes  # reset demo seed data
```

For a standalone container, stop and remove it, then drop the image:

```bash
docker rm -f trstctl
docker image rm "$TRSTCTL_IMAGE_REF"   # e.g. ghcr.io/ctlplne/trstctl@sha256:<release-image-digest>
```

## Kubernetes

Delete the agent DaemonSet and its supporting objects (deleting the namespace
removes everything in it):

```bash
kubectl delete -f deploy/kubernetes/daemonset.yaml
kubectl delete -f deploy/kubernetes/rbac.yaml
kubectl delete -f deploy/kubernetes/namespace.yaml
```

The DaemonSet stores the node agent identity under `/var/lib/trstctl-agent` on
each node through a hostPath. Remove that host directory only if you are fully
decommissioning the node identity or intentionally forcing future re-enrollment.

## Linux

Stop and disable the service, then remove the binaries:

```bash
sudo systemctl disable --now trstctl-agent
sudo rm -f /etc/systemd/system/trstctl-agent.service
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/trstctl /usr/local/bin/trstctl-agent /usr/local/bin/trstctl-signer
```

Optionally remove the agent's local state directory (its data dir and the
telemetry instance ID, if you enabled telemetry).

## macOS

Unload the `launchd` job and remove the binary:

```bash
sudo launchctl unload /Library/LaunchDaemons/io.trstctl.agent.plist
sudo rm -f /Library/LaunchDaemons/io.trstctl.agent.plist
sudo rm -f /usr/local/bin/trstctl-agent
```

Certificates the agent placed in the keychain remain until you remove them.

## Windows

Uninstall the MSI, which stops and unregisters the SCM service:

```powershell
msiexec /x trstctl-agent.msi /qn
```

Or remove **trstctl agent** from *Settings → Apps*. Certificates already in the
Windows certificate store are left in place.

## Remove the datastore (optional)

trstctl's own state lives entirely in PostgreSQL and NATS JetStream. If you ran
external datastores and want trstctl gone completely, drop its database and
JetStream streams on those servers. With the bundled Compose datastores, the
`down --volumes` command above already removed them.
