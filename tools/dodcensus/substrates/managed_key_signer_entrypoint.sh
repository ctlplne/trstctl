#!/bin/sh
set -eu

: "${TRSTCTL_DOD_PROVIDER:?TRSTCTL_DOD_PROVIDER is required}"
mkdir -p /runtime /runtime/keystore /runtime/tokens /runtime/tpm-state
chmod 0700 /runtime/keystore /runtime/tokens /runtime/tpm-state

case "$TRSTCTL_DOD_PROVIDER" in
  aws|azure-key-vault|gcp-kms)
    : "${TRSTCTL_DOD_CLOUD_UPSTREAM:?TRSTCTL_DOD_CLOUD_UPSTREAM is required for cloud-provider proof}"
    # The shipped signer is allowed to use plaintext only on its own loopback.
    # This DoD-only sidecar relay keeps the protocol-faithful emulator on the
    # isolated Docker network while the signer dials 127.0.0.1 under the explicit
    # allow_insecure_loopback development switch.
    socat TCP-LISTEN:18080,bind=127.0.0.1,reuseaddr,fork TCP:"$TRSTCTL_DOD_CLOUD_UPSTREAM" &
    relay_pid=$!
    sleep 0.1
    kill -0 "$relay_pid"
    ;;
  pkcs11|yubihsm2)
    module="$(find /usr/lib -name libsofthsm2.so -type f -print -quit)"
    test -n "$module"
    ln -sf "$module" /runtime/libsofthsm2.so
    cat >/runtime/softhsm2.conf <<'EOF'
directories.tokendir = /runtime/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF
    export SOFTHSM2_CONF=/runtime/softhsm2.conf
    if ! softhsm2-util --show-slots | grep -q 'Label: *trstctl-dod'; then
      softhsm2-util --init-token --free --label trstctl-dod --so-pin 3537363231383830 --pin 12345678 >/dev/null
    fi
    ;;
  tpm2)
    swtpm socket --tpm2 --tpmstate dir=/runtime/tpm-state \
      --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
      --flags startup-clear --seccomp action=none --daemon
    socat UNIX-LISTEN:/tmp/swtpm.sock,fork,mode=0600,unlink-early TCP:127.0.0.1:2321 &
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      test -S /tmp/swtpm.sock && break
      sleep 0.1
    done
    test -S /tmp/swtpm.sock
    ;;
esac

exec /usr/local/bin/trstctl-signer-hsm "$@"
