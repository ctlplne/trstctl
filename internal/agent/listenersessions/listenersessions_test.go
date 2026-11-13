// SPDX-License-Identifier: BUSL-1.1

package listenersessions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeProc writes a proc tree: a TCP table, a boot time, and processes each
// with a start (seconds after boot) and the socket inodes it holds. A
// process with a negative start has an unreadable descriptor directory.
type fakeProcess struct {
	pid     int
	comm    string
	startS  int
	inodes  []string
	private bool
}

func fakeProc(t *testing.T, boot int64, tcp, tcp6 []string, procs []fakeProcess) string {
	t.Helper()
	root := t.TempDir()
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	write(filepath.Join(root, "net", "tcp"), header+strings.Join(tcp, "\n")+"\n")
	if tcp6 != nil {
		write(filepath.Join(root, "net", "tcp6"), header+strings.Join(tcp6, "\n")+"\n")
	}
	write(filepath.Join(root, "stat"), fmt.Sprintf("cpu  1 2 3 4\nbtime %d\nprocesses 9\n", boot))
	for _, p := range procs {
		dir := filepath.Join(root, fmt.Sprint(p.pid))
		// Field 22 is the start in clock ticks; the name may hold ") (".
		fields := make([]string, 0, 50)
		fields = append(fields, "S")
		for i := 4; i <= 21; i++ {
			fields = append(fields, "0")
		}
		fields = append(fields, fmt.Sprint(p.startS*userHZ), "0", "0")
		write(filepath.Join(dir, "stat"), fmt.Sprintf("%d (%s) %s\n", p.pid, p.comm, strings.Join(fields, " ")))
		fd := filepath.Join(dir, "fd")
		if err := os.MkdirAll(fd, 0o750); err != nil {
			t.Fatal(err)
		}
		for i, inode := range p.inodes {
			if err := os.Symlink("socket:["+inode+"]", filepath.Join(fd, fmt.Sprint(3+i))); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink("/dev/null", filepath.Join(fd, "0")); err != nil {
			t.Fatal(err)
		}
		if p.private {
			if err := os.Chmod(fd, 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(fd, 0o700) }) // #nosec G302 -- a test directory restored so TempDir can remove it
		}
	}
	return root
}

func tcpRow(local, state, inode string) string {
	return "   0: " + local + " 0100007F:D431 " + state + " 00000000:00000000 00:00000000 00000000  1000        0 " + inode + " 1 0000000000000000 20 4 30 10 -1"
}

// A245-L2: the established connections on the listener's port are counted
// across both TCP tables, each attributed to the processes holding it; one
// held by any process older than the moment counts as held by an older
// process, one whose holder cannot be read counts as unattributed, and a
// listening socket, another port or another state is not counted.
func TestObserveSplitsConnectionsByHolderAgeA245L2(t *testing.T) {
	const boot = 1_700_000_000
	since := time.Unix(boot+1000, 0)
	root := fakeProc(t, boot,
		[]string{
			tcpRow("00000000:01BB", "0A", "100"), // the listening socket
			tcpRow("0100007F:01BB", "01", "201"), // held by the old worker
			tcpRow("0100007F:01BB", "01", "202"), // held by the new worker
			tcpRow("0100007F:01BB", "01", "203"), // held by both: older wins
			tcpRow("0100007F:1F90", "01", "204"), // another port
			tcpRow("0100007F:01BB", "06", "205"), // TIME_WAIT
			tcpRow("0100007F:01BB", "01", "206"), // holder unreadable
		},
		[]string{
			tcpRow("00000000000000000000000001000000:01BB", "01", "301"), // IPv6, new worker
		},
		[]fakeProcess{
			{pid: 10, comm: "nginx: worker (old) ) x", startS: 500, inodes: []string{"201", "203"}},
			{pid: 11, comm: "nginx", startS: 1500, inodes: []string{"202", "203", "301", "204"}},
			{pid: 12, comm: "private", startS: 100, inodes: []string{"206"}, private: os.Geteuid() != 0},
		})
	got, err := observeProc(root, 443, since, time.Unix(boot+2000, 0))
	if err != nil {
		t.Fatal(err)
	}
	wantUnattributed := 1
	wantOlder := 2
	if os.Geteuid() == 0 { // root reads every descriptor directory
		wantUnattributed, wantOlder = 0, 3
	}
	want := Observation{Port: 443, Established: 5, HeldByOlder: wantOlder, Unattributed: wantUnattributed,
		SinceUnix: boot + 1000, CheckedAtUnix: boot + 2000}
	if got != want || !got.Valid() {
		t.Fatalf("observation = %+v; want %+v", got, want)
	}

	// Once the old worker has exited, nothing older holds a connection.
	root = fakeProc(t, boot, []string{tcpRow("0100007F:01BB", "01", "202")}, nil,
		[]fakeProcess{{pid: 11, comm: "nginx", startS: 1500, inodes: []string{"202"}}})
	if got, err := observeProc(root, 443, since, time.Unix(boot+2000, 0)); err != nil || got.Established != 1 || got.HeldByOlder != 0 || got.Unattributed != 0 {
		t.Fatalf("after the old worker exited: %+v, %v", got, err)
	}
	// No connection at all needs no process table.
	root = fakeProc(t, boot, []string{tcpRow("00000000:01BB", "0A", "100")}, nil, nil)
	if got, err := observeProc(root, 443, since, time.Unix(boot+2000, 0)); err != nil || got.Established != 0 || !got.Valid() {
		t.Fatalf("an idle listener: %+v, %v", got, err)
	}
	if _, err := observeProc(root, 0, since, time.Unix(boot+2000, 0)); err == nil {
		t.Fatal("port 0 was accepted")
	}
}

// Valid refuses counts that cannot hold together.
func TestObservationValidA245L2(t *testing.T) {
	ok := Observation{Port: 443, Established: 3, HeldByOlder: 1, Unattributed: 2, SinceUnix: 10, CheckedAtUnix: 10}
	if !ok.Valid() {
		t.Fatal("a consistent observation is invalid")
	}
	for name, bad := range map[string]Observation{
		"more held than established": {Port: 443, Established: 1, HeldByOlder: 1, Unattributed: 1, SinceUnix: 10, CheckedAtUnix: 10},
		"checked before since":       {Port: 443, Established: 0, SinceUnix: 11, CheckedAtUnix: 10},
		"no port":                    {Established: 0, SinceUnix: 10, CheckedAtUnix: 10},
		"negative":                   {Port: 443, Established: -1, SinceUnix: 10, CheckedAtUnix: 10},
	} {
		if bad.Valid() {
			t.Fatalf("%s: valid", name)
		}
	}
}
