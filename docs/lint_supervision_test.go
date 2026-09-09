// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"os/exec"
	"testing"
)

// Run real scanner/child processes. A delayed marker catches children that keep
// running after the gate has returned, even if they have closed their output.
func TestEELintScannerSupervision(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "timeout", "term", "interrupt", "outer-term", "leader-exit", "stdout-limit", "stderr-limit", "spawn-failure"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(python, "-B", "-c", lintSupervisionControl, mode, t.TempDir()) // #nosec G204 -- fixed supervision regression with owned scanner and child fixtures (CWE-78)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("scanner supervision %s: %v\n%s", mode, err, out)
			}
		})
	}
}

const lintSupervisionControl = `
import os, pathlib, signal, subprocess, sys, time
mode, root = sys.argv[1], pathlib.Path(sys.argv[2])
module = pathlib.Path("../scripts/ci/ee-lint-ratchet.py").resolve()
scanner = root / "scanner.py"
runner = root / "runner.py"
scanner.write_text('''
import os, pathlib, signal, subprocess, sys, time
root, mode = pathlib.Path(sys.argv[1]), sys.argv[2]
(root / "scanner.pid").write_text(str(os.getpid()))
if mode != "success":
    child = subprocess.Popen([sys.executable, "-c", "import pathlib,signal,sys,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); signal.signal(signal.SIGINT,signal.SIG_IGN); pathlib.Path(sys.argv[1]).write_text('ready'); time.sleep(1); pathlib.Path(sys.argv[2]).write_text('survived')", str(root / "child.ready"), str(root / "survived")])
    while not (root / "child.ready").exists(): time.sleep(.005)
print("partial scanner stdout", flush=True)
print("partial scanner stderr", file=sys.stderr, flush=True)
(root / "ready").write_text("ready")
if mode == "stdout-limit": sys.stdout.write("x" * 70000); sys.stdout.flush()
if mode == "stderr-limit": sys.stderr.write("x" * 70000); sys.stderr.flush()
if mode not in ("success", "leader-exit"): time.sleep(60)
''')
runner.write_text('''
import importlib.util, pathlib, sys
module, scanner, root, mode = sys.argv[1:]
spec = importlib.util.spec_from_file_location("ee_lint", module)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.MAX_REPORT_BYTES = 65536
try:
    command = [str(pathlib.Path(root) / "missing-scanner")] if mode == "spawn-failure" else [sys.executable, scanner, root, mode]
    code, raw = m.run_scanner(command, timeout=.2 if mode == "timeout" else 5)
    sys.exit(code)
except Exception as exc:
    print(type(exc).__name__ + ": " + str(exc), file=sys.stderr)
    sys.exit(2)
''')
p = subprocess.Popen([sys.executable, "-B", str(runner), str(module), str(scanner), str(root), mode], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
def stop(group, sig):
    # macOS may return EPERM for a group containing only our unreaped zombie.
    # Reap the directly owned leader before signalling its surviving children.
    if group == p.pid: p.poll()
    try: os.killpg(group, sig)
    except ProcessLookupError: pass
try:
    if mode in ("term", "interrupt", "outer-term"):
        deadline = time.monotonic() + 3
        while not (root / "ready").exists():
            assert time.monotonic() < deadline and p.poll() is None, "scanner did not become ready"
            time.sleep(.005)
        if mode == "outer-term":
            # Match the enclosing harness's TERM-to-KILL interval. Its KILL
            # cannot reach the scanner's separate group, so forwarding matters.
            stop(p.pid, signal.SIGTERM)
            time.sleep(.15)
            stop(p.pid, signal.SIGKILL)
        else:
            os.kill(p.pid, signal.SIGTERM if mode == "term" else signal.SIGINT)
    output, _ = p.communicate(timeout=6)
    assert p.returncode == (0 if mode == "success" else 2), (p.returncode, output)
    if mode != "spawn-failure":
        assert b"partial scanner stdout" in output, output
        if mode != "stdout-limit": assert b"partial scanner stderr" in output, output
    expected = {"timeout": b"TimeoutExpired", "term": b"cancelled by signal 15", "interrupt": b"cancelled by signal 2", "outer-term": b"cancelled by signal 15", "leader-exit": b"surviving children", "stdout-limit": b"output exceeds", "stderr-limit": b"output exceeds", "spawn-failure": b"FileNotFoundError"}
    if mode in expected: assert expected[mode] in output, output
    time.sleep(1.1)
    assert not (root / "survived").exists(), "scanner child ran after gate exit"
    if (root / "scanner.pid").exists():
        group = int((root / "scanner.pid").read_text())
        try: os.killpg(group, 0)
        except ProcessLookupError: pass
        else: raise AssertionError("scanner process group survived gate exit")
finally:
    # Only groups created by this fixture are eligible for cleanup.
    stop(p.pid, signal.SIGKILL)
    if (root / "scanner.pid").exists():
        stop(int((root / "scanner.pid").read_text()), signal.SIGKILL)
    p.communicate(timeout=3)
`
