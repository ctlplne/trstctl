// SPDX-License-Identifier: BUSL-1.1
//go:build windows

package windependents

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Keep this wire input native-only: importing the receiver or its domain from
// this crypto package would create a dependency cycle. The separate receiver
// executable decodes the same bounded input and builds the actual domain steps.
type ownedDependentExecutorInput struct {
	SID      string
	Services []Service
	Tasks    []Task
	Pools    []Pool
	Probes   map[string]string
	StateDir string
	Failure  string
	Old      secret.JSONBytes `json:"Old,omitempty"`
	Next     secret.JSONBytes `json:"Next,omitempty"`
}
type ownedDependentExecutorMessage struct {
	Request   string `json:"request"`
	Family    string `json:"family,omitempty"`
	Action    string `json:"action,omitempty"`
	Direction string `json:"direction,omitempty"`
	Status    string `json:"status,omitempty"`
	Failure   string `json:"failure,omitempty"`
}

func nativeReserveLoopback(t *testing.T) string {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	if e = listener.Close(); e != nil {
		t.Fatal(e)
	}
	return address
}

// The bridge obtains work from the actual service/pool process or the task's
// protected work receipt. It returns public evidence, never credential bytes.
func nativeDependentWorkBridge(t *testing.T, serviceAddress, poolAddress, work, sid string) map[string]string {
	t.Helper()
	for _, address := range []string{serviceAddress, poolAddress} {
		endpoint, err := netip.ParseAddrPort(address)
		if err != nil || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 {
			t.Fatal("native work endpoint must be a literal loopback listener")
		}
	}
	workInfo, err := os.Lstat(work) // #nosec G703 -- only the parent-created ACL-restricted native fixture directory, before installing the request handler (CWE-22)
	if err != nil || !filepath.IsAbs(work) || !workInfo.IsDir() || workInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatal("owned native work directory unavailable")
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("owned native bridge refuses redirects") }}
	t.Cleanup(client.CloseIdleConnections)
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenge := r.URL.Query().Get("challenge")
		nonce := strings.ReplaceAll(challenge, "-", "")
		decoded, e := hex.DecodeString(nonce)
		if e != nil || len(decoded) != 16 || len(challenge) != 36 {
			http.Error(w, "invalid owned challenge", http.StatusBadRequest)
			return
		}
		family := strings.TrimPrefix(r.URL.Path, "/")
		if family != "services" && family != "tasks" && family != "iis" && family != "failtask" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPost && (family == "tasks" || family == "failtask") && r.URL.Query().Get("phase") == "prepare" {
			if e = os.WriteFile(filepath.Join(work, "nonce"), []byte(nonce), 0o600); e != nil { // #nosec G703 -- validated parent-owned directory plus constant filename; request-derived nonce is validated hex file content only (CWE-22)
				http.Error(w, "owned challenge write failed", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet || r.URL.Query().Get("phase") != "verify" {
			http.Error(w, "invalid owned work method", http.StatusBadRequest)
			return
		}
		var raw []byte
		var pid uint32
		if family == "tasks" || family == "failtask" {
			if family == "failtask" {
				http.Error(w, "injected functional failure after native completion", http.StatusServiceUnavailable)
				return
			}
			f, e := os.Open(filepath.Join(work, "receipt.json")) // #nosec G304 -- fixed public receipt under the exact test-owned protected native task work directory (CWE-22)
			if e != nil {
				http.Error(w, "owned task work unavailable", http.StatusServiceUnavailable)
				return
			}
			raw, e = io.ReadAll(io.LimitReader(f, 4097))
			_ = f.Close()
			var receipt nativeTaskWorkReceipt
			if e != nil || len(raw) > 4096 || json.Unmarshal(raw, &receipt) != nil || receipt.Nonce != nonce || receipt.SID != sid || receipt.PID == 0 || receipt.Result != crypto.SHA256Hex([]byte("task-work:"+nonce)) {
				http.Error(w, "owned task work differs", http.StatusServiceUnavailable)
				return
			}
		} else {
			path := "http://" + serviceAddress + "/work?nonce=" + nonce
			if family == "iis" {
				path = "http://" + poolAddress + "/default.aspx?nonce=" + nonce
			}
			request, e := http.NewRequestWithContext(r.Context(), http.MethodGet, path, nil) // #nosec G704 -- both exact listener addresses validated as literal loopback before handler installation; only a validated 16-byte hex nonce varies (CWE-918)
			if e != nil {
				http.Error(w, "invalid owned work address", http.StatusInternalServerError)
				return
			}
			response, e := client.Do(request) // #nosec G704 -- fixed validated loopback origin, bounded client and all redirects refused (CWE-918)
			if e != nil {
				http.Error(w, "owned process work unavailable", http.StatusServiceUnavailable)
				return
			}
			raw, e = io.ReadAll(io.LimitReader(response.Body, 4097))
			_ = response.Body.Close()
			if e != nil || len(raw) > 4096 || response.StatusCode != 200 {
				http.Error(w, "owned process work failed", http.StatusServiceUnavailable)
				return
			}
			if family == "services" {
				var receipt nativeWorkReceipt
				if json.Unmarshal(raw, &receipt) != nil || receipt.SID != sid || receipt.PID == 0 || receipt.Result != crypto.SHA256Hex([]byte("service-work:"+nonce)) {
					http.Error(w, "owned service work differs", http.StatusServiceUnavailable)
					return
				}
				pid = receipt.PID
			} else {
				var receipt nativePoolWorkReceipt
				if json.Unmarshal(raw, &receipt) != nil || receipt.Nonce != nonce || receipt.SID != sid || receipt.PID == 0 || receipt.Result != crypto.SHA256Hex([]byte("pool-work:"+nonce)) {
					http.Error(w, "owned pool work differs", http.StatusServiceUnavailable)
					return
				}
				pid = receipt.PID
			}
		}
		proof := map[string]any{"probe_id": family, "challenge": challenge, "account_sid": sid, "evidence_sha256": crypto.SHA256Hex(raw)}
		if pid != 0 {
			proof["process_id"] = pid
		}
		if family == "tasks" {
			proof["task_instance_id"] = r.URL.Query().Get("task_instance_id")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	root := "http://" + listener.Addr().String()
	return map[string]string{"services": root + "/services", "tasks": root + "/tasks", "iis": root + "/iis", "failtask": root + "/failtask"}
}
func TestNativeWindowsDependentExecutorLifecycleA267(t *testing.T) {
	if os.Getenv("TRSTCTL_A267_WINDOWS_EXECUTOR") != "1" {
		t.Skip("owned native receiver coordination lab not requested")
	}
	executable := os.Getenv("TRSTCTL_A267_NATIVE_EXECUTOR")
	info, e := os.Lstat(executable) // #nosec G703 -- explicit local lab artifact reference, required absolute regular non-symlink file and exact build hash below (CWE-22)
	if e != nil || !filepath.IsAbs(executable) || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256<<20 {
		t.Fatal("exact compiled native receiver executable unavailable")
	}
	file, e := os.Open(executable) // #nosec G304 G703 -- same bounded regular lab executable, read only to compare the independently recorded compiler-output digest (CWE-22)
	if e != nil {
		t.Fatal(e)
	}
	digest, size, hashErr := crypto.SHA256ReaderHex(io.LimitReader(file, 256<<20+1))
	closeErr := file.Close()
	if hashErr != nil || closeErr != nil || size != info.Size() || digest != os.Getenv("TRSTCTL_A267_NATIVE_EXECUTOR_SHA256") {
		t.Fatal("native receiver differs from the exact compiled lab artifact")
	}
	for _, failure := range []string{"", "update", "functional"} {
		name := failure
		if name == "" {
			name = "forward"
		}
		t.Run(name, func(t *testing.T) { nativeDependentExecutorScenario(t, executable, failure) })
	}
	t.Log("A267_WINDOWS_EXECUTOR_OK: shipped receiver native service/task/IIS steps, fresh useful work, exact task replay and directory-first inverse after update/functional failure; local SAM is not AD or a joined forest")
}
func nativeDependentExecutorScenario(t *testing.T, executable, failure string) {
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Minute)
	defer cancel()
	if e := taskEventsEnabled(); e != nil {
		t.Fatal(e)
	}
	random, e := crypto.RandomBytes(4)
	if e != nil {
		t.Fatal(e)
	}
	suffix := hex.EncodeToString(random)
	name := "trst267_" + suffix
	old, next := nativeOwnedPassword(t), nativeOwnedPassword(t)
	sid := nativeCreateOwnedAccount(t, name, old.Bytes())
	nativeGrantOwnedAccountRight(t, sid, "SeBatchLogonRight")
	binary := nativeOwnedServiceBinary(t, suffix, sid.String())
	serviceAddress := nativeReserveLoopback(t)
	_, initial := nativeCreateOwnedServiceFixture(t, ctx, name, "trstctl-a267-"+suffix, binary, serviceAddress, sid.String(), old.Bytes())
	nativeFunctionalWork(t, ctx, serviceAddress, initial)
	work := nativeOwnedTaskWorkDirectory(t, suffix, sid.String())
	taskPath := nativeCreateOwnedTask(t, ctx, "trstctl-a267-task-"+suffix, ".\\"+name, binary, work, old.Bytes())
	taskAdapter, e := NewTasks(TaskExecutionPolicy{VerificationPaths: []string{taskPath}})
	if e != nil {
		t.Fatal(e)
	}
	iisDirectory := nativeOwnedIISDirectory(t, suffix, sid.String())
	poolName := "trstctl-a267-pool-" + suffix
	poolAddress := nativeReserveLoopback(t)
	createOwnedIISPool(t, ctx, poolName, ".\\"+name, old.Bytes())
	createOwnedIISSite(t, ctx, "trstctl-a267-site-"+suffix, poolName, iisDirectory, poolAddress, 100000+uint32(random[0])*256+uint32(random[1]))
	_ = nativeIISWork(t, ctx, poolAddress, sid.String())
	services, e := NewServices().Discover(ctx, sid.String())
	if e != nil || len(services) != 1 {
		t.Fatal("exact owned service snapshot unavailable")
	}
	tasks, e := taskAdapter.Discover(ctx, sid.String())
	if e != nil || len(tasks) != 1 {
		t.Fatal("exact owned task snapshot unavailable")
	}
	pools, e := NewPools().Discover(ctx, sid.String())
	if e != nil || len(pools) != 1 {
		t.Fatal("exact owned pool snapshot unavailable")
	}
	input := ownedDependentExecutorInput{SID: sid.String(), Services: services, Tasks: tasks, Pools: pools, Probes: nativeDependentWorkBridge(t, serviceAddress, poolAddress, work, sid.String()), StateDir: t.TempDir(), Failure: failure, Old: secret.JSONBytes(old.Bytes()), Next: secret.JSONBytes(next.Bytes())}
	public := input
	public.Old, public.Next = nil, nil
	raw, e := json.Marshal(public)
	if e != nil {
		t.Fatal("owned receiver metadata encoding failed")
	}
	for _, field := range []struct {
		name  string
		value []byte
	}{{"Old", old.Bytes()}, {"Next", next.Bytes()}} {
		quoted, err := secret.JSONBytes(field.value).MarshalJSON()
		if err != nil {
			secret.Wipe(raw)
			t.Fatal(err)
		}
		nextWire := make([]byte, 0, len(raw)+len(quoted)+len(field.name)+5)
		nextWire = append(nextWire, raw[:len(raw)-1]...)
		nextWire = append(nextWire, []byte(",\""+field.name+"\":")...)
		nextWire = append(nextWire, quoted...)
		nextWire = append(nextWire, '}')
		secret.Wipe(quoted)
		secret.Wipe(raw)
		raw = nextWire
	}
	held, e := secret.NewFrom(raw)
	secret.Wipe(raw)
	if e != nil {
		t.Fatal(e)
	}
	defer held.Destroy()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestNativeWindowsDependentExecutorChildA267$", "-test.v") // #nosec G204 G702 -- exact compiler-output digest verified by the parent; absolute regular lab binary, fixed argv, no shell or credential argument (CWE-78)
	command.Env = append(os.Environ(), "TRSTCTL_A267_NATIVE_CHILD=1")
	stdin, e := command.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	stdout, e := command.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	command.Stderr = io.Discard
	if e = command.Start(); e != nil {
		t.Fatal("owned receiver child did not start")
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	if _, e = stdin.Write(held.Bytes()); e != nil {
		t.Fatal("owned receiver pipe failed")
	}
	held.Destroy()
	if _, e = stdin.Write([]byte("\n")); e != nil {
		t.Fatal(e)
	}
	scanner := bufio.NewScanner(io.LimitReader(stdout, 4<<20))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	resets := []string{}
	counts := map[string]int{}
	done := false
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "A267_MESSAGE ") {
			continue
		}
		var message ownedDependentExecutorMessage
		if json.Unmarshal([]byte(strings.TrimPrefix(line, "A267_MESSAGE ")), &message) != nil {
			t.Fatal("owned receiver public report malformed")
		}
		switch message.Request {
		case "reset_new", "reset_old":
			resets = append(resets, message.Request)
			password := next.Bytes()
			if message.Request == "reset_old" {
				password = old.Bytes()
			}
			nativeSetOwnedPassword(t, name, password)
			if _, e = io.WriteString(stdin, "{\"OK\":true}\n"); e != nil {
				t.Fatal("owned reset acknowledgement failed")
			}
		case "step":
			counts[message.Direction+":"+message.Action+":"+message.Family+":"+message.Status]++
			t.Logf("native receiver %s %s %s: %s %s", message.Direction, message.Action, message.Family, message.Status, message.Failure)
		case "done":
			done = true
		default:
			t.Fatal("owned receiver sent an unknown request")
		}
	}
	_ = stdin.Close()
	if e = scanner.Err(); e != nil {
		t.Fatal("owned receiver public output failed")
	}
	if e = command.Wait(); e != nil || !done {
		t.Fatal("owned receiver native execution failed; see the last public step")
	}
	if len(resets) != 1 && failure == "" || len(resets) != 2 && failure != "" || resets[0] != "reset_new" || failure != "" && resets[1] != "reset_old" {
		t.Fatal("native directory/reset order differs")
	}
	for _, family := range []string{"services", "tasks", "iis"} {
		if counts["forward:preflight:"+family+":succeeded"] != 1 {
			t.Fatal("native preflight missing")
		}
		direction := "forward"
		if failure != "" {
			direction = "inverse"
		}
		if counts[direction+":probe:"+family+":succeeded"] != 1 {
			t.Fatal("fresh native useful work missing after change or inverse")
		}
	}
	if failure == "" {
		if nativeOwnedSignIn(t, name, old.Bytes()) || !nativeOwnedSignIn(t, name, next.Bytes()) {
			t.Fatal("native forward credential acceptance differs")
		}
	} else {
		if !nativeOwnedSignIn(t, name, old.Bytes()) || nativeOwnedSignIn(t, name, next.Bytes()) {
			t.Fatal("native inverse credential acceptance differs")
		}
	}
	// The bridge checks real work; the receiver separately binds its SID/PID or
	// task instance to native observations and rejects reused predecessor workers.
}
