# Runbook: install a production control plane

This runbook installs the control plane against external PostgreSQL and NATS and
proves it before it takes traffic. The options behind each step are in
[Install](../install.md) and [Configuration](../configuration.md).

## Prerequisites

- External PostgreSQL (`TRSTCTL_POSTGRES_MODE=external`, `TRSTCTL_POSTGRES_DSN`)
  and external NATS with JetStream (`TRSTCTL_NATS_MODE=external`,
  `TRSTCTL_NATS_URL`). The bundled modes are for evaluation.
- The deployment KEK in separate key custody (`kek.existingSecret` for the Helm
  chart, `TRSTCTL_SECRETS_KEK_FILE` otherwise). A backup never contains it.
- A backup directory on storage outside the control plane's
  (`TRSTCTL_BACKUP_DIRECTORY`).
- The release image pinned by digest and verified:
  `scripts/verify-image.sh "$TRSTCTL_IMAGE_REF"`.

## Steps

1. Check the configuration. It exits non-zero on a bad configuration, and the
   DSN and NATS URL print redacted:

    ```sh
    trstctl --check-config
    ```

2. Check the database. On a new database the preflight reports `ready` and
   `rollback: rerun`; anything else means the database is not new:

    ```sh
    trstctl --upgrade-preflight
    ```

3. Install with the Helm chart (`helm install trstctl deploy/helm/trstctl ...`,
   as in [Install](../install.md#kubernetes-control-plane-via-helm)) or the
   Compose stack for one host. The first start applies the schema.
4. Wait for readiness: `/readyz` answers `200` (`trstctl --ready-check` exits 0
   in the container) and `trstctl_signer_up == 1`.
5. Take the first full backup into the backup directory:

    ```sh
    trstctl --full-backup-dir="$TRSTCTL_BACKUP_DIRECTORY"
    ```

6. Let the scheduled restore drill run (`TRSTCTL_BACKUP_DRILL_INTERVAL`, daily
   by default) and read **Deployment health** on the Operations page: backup
   freshness and restore proof both `ok`.

## Abort criteria

- `--check-config` or `--upgrade-preflight` exits non-zero.
- `/readyz` does not reach `200`, or `trstctl_signer_up` stays `0`.
- The first drill is `failed`: its detail names the check that failed.

## Evidence to retain

The image digest and its verification output, the `--check-config` and
`--upgrade-preflight` output, and the first drill's signed attestation.
