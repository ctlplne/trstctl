// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestConnectorSubstrateRejectsArbitrarySignalsAndReadbackPaths(t *testing.T) {
	repo := filepath.Clean(filepath.Join("..", ".."))
	target := filepath.Join(repo, "tools", "dodcensus", "substrates", "connector_target.py")
	const source = `
import pathlib
import runpy
import sys
import tempfile

sys.dont_write_bytecode = True
ns = runpy.run_path(sys.argv[1])
State = ns["State"]

sequences = {
    "connector.nginx": [("nginx", ["-t"]), ("nginx", ["-s", "reload"])],
    "connector.apache": [("apachectl", ["configtest"]), ("apachectl", ["graceful"])],
    "connector.caddy": [("caddy", ["reload"])],
    "connector.haproxy": [("haproxy", ["-c", "-f", "/target/haproxy.cfg"]), ("systemctl", ["reload", "haproxy"])],
    "connector.postfix": [("postfix", ["check"]), ("doveconf", ["-n"]), ("postfix", ["reload"]), ("doveadm", ["reload"])],
    "connector.postgresql": [("pg_ctl", ["reload"])],
    "connector.mysql": [("mysqladmin", ["reload"])],
    "connector.rabbitmq": [("rabbitmqctl", ["rotate_certs"])],
    "connector.tomcat": [("catalina.sh", ["reload"])],
}

for entry, sequence in sequences.items():
    root = pathlib.Path(tempfile.mkdtemp())
    state = State(entry, root)
    state.readback = b"independent certificate readback"
    for logical, args in sequence:
        assert state.record_signal({"entry_id": entry, "logical": logical, "args": args})
    assert state.passed(), entry
    assert not state.record_signal({"entry_id": entry, "logical": sequence[-1][0], "args": sequence[-1][1]}), entry
    assert not state.passed(), entry

    wrong = State(entry, root)
    logical, args = sequence[0]
    assert not wrong.record_signal({"entry_id": "connector.attacker", "logical": logical, "args": args})
    assert not wrong.record_signal({"entry_id": entry, "logical": logical, "args": args + ["attacker"]})
    assert not wrong.passed()

root = pathlib.Path(tempfile.mkdtemp())
nginx = State("connector.nginx", root)
assert nginx.readback_path_ok((root / "server.crt").resolve())
assert not nginx.readback_path_ok((root / "attacker.crt").resolve())
assert not nginx.readback_path_ok((root / "server.key").resolve())

iis_root = pathlib.Path(tempfile.mkdtemp())
import_dir = iis_root / "import"
pfx = import_dir / "fingerprint.pfx"
pw = import_dir / "fingerprint.pw"
command = (
    f"$pfx='{pfx}'; $pwPath='{pw}'; try {{ Import-PfxCertificate -FilePath $pfx "
    "-CertStoreLocation Cert:\\LocalMachine\\MY -Password $sec | Out-Null } "
    "finally { Remove-Item -LiteralPath $pfx,$pwPath -Force }"
)
iis = State("connector.iis", iis_root)
valid = [
    ("powershell", ["-NoProfile", "-NonInteractive", "-Command", command]),
    ("netsh", ["http", "delete", "sslcert", "ipport=0.0.0.0:443"]),
    ("netsh", ["http", "add", "sslcert", "ipport=0.0.0.0:443", "certhash=" + "A" * 40, "appid={4dc3e181-e14b-4a21-b022-59fc669b0914}", "certstorename=MY"]),
]
for logical, args in valid:
    assert iis.record_signal({"entry_id": "connector.iis", "logical": logical, "args": args})
iis.readback = b"imported certificate"
assert iis.passed()

outside = State("connector.iis", iis_root)
bad_command = command.replace(str(import_dir), str(iis_root / "attacker"))
assert not outside.record_signal({"entry_id": "connector.iis", "logical": "powershell", "args": ["-NoProfile", "-NonInteractive", "-Command", bad_command]})
assert not outside.passed()
`
	command := exec.Command("python3", "-c", source, target)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("connector substrate contract adversary failed: %v\n%s", err, output)
	}
}
