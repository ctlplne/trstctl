// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
)

// kubeExecPeer plays the gateway's side of a browser terminal's exec: the
// HTTP upgrade, then WebSocket frames.
type kubeExecPeer struct {
	c  net.Conn
	br *bufio.Reader
}

// send writes one unmasked server frame.
func (p kubeExecPeer) send(opcode byte, fin bool, payload []byte) error {
	head := opcode
	if fin {
		head |= 0x80
	}
	frame := []byte{head}
	switch n := len(payload); {
	case n < 126:
		frame = append(frame, byte(n)) // #nosec G115 -- test frame length below 126 (CWE-190)
	case n < 1<<16:
		frame = append(frame, 126)
		frame = binary.BigEndian.AppendUint16(frame, uint16(n)) // #nosec G115 -- test frame length under 1<<16 (CWE-190)
	default:
		frame = append(frame, 127)
		frame = binary.BigEndian.AppendUint64(frame, uint64(n)) // #nosec G115 -- test frame length, never negative (CWE-190)
	}
	_, err := p.c.Write(append(frame, payload...))
	return err
}

// receive reads one client frame, which must be masked, and returns its
// opcode and unmasked payload.
func (p kubeExecPeer) receive() (byte, []byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(p.br, head); err != nil {
		return 0, nil, err
	}
	if head[0]&0x80 == 0 || head[1]&0x80 == 0 {
		return 0, nil, fmt.Errorf("a client frame must be final and masked: % x", head)
	}
	length := uint64(head[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(p.br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(p.br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	mask := make([]byte, 4)
	if _, err := io.ReadFull(p.br, mask); err != nil {
		return 0, nil, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(p.br, payload); err != nil {
		return 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return head[0] & 0x0f, payload, nil
}

// upgrade reads the exec request and answers it.
func (p kubeExecPeer) upgrade(answer string) (*http.Request, error) {
	req, err := http.ReadRequest(p.br)
	if err != nil {
		return nil, err
	}
	_, err = io.WriteString(p.c, answer)
	return req, err
}

const kubeExecSwitched = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: v5.channel.k8s.io\r\n\r\n"

// TestKubeExecStreamA259: the browser terminal's exec upgrades the admitted
// connection with the pod, container and command it names, reads output
// from channels 1 and 2 across fragments and long frames while answering
// pings, sends typed input on channel 0 and a resize on channel 4 in masked
// frames, and ends with the exit status from channel 3.
func TestKubeExecStreamA259(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	peer := kubeExecPeer{c: server, br: bufio.NewReader(server)}
	long := strings.Repeat("x", 300)
	type seen struct {
		req           *http.Request
		input, resize []byte
		closeOpcode   byte
	}
	result := make(chan seen, 1)
	failed := make(chan error, 1)
	go func() {
		defer func() { _ = server.Close() }()
		var got seen
		err := func() error {
			var err error
			if got.req, err = peer.upgrade(kubeExecSwitched); err != nil {
				return err
			}
			if err := peer.send(0x9, true, []byte("p1")); err != nil {
				return err
			}
			if opcode, payload, err := peer.receive(); err != nil || opcode != 0xA || string(payload) != "p1" {
				return fmt.Errorf("pong = %x %q %v", opcode, payload, err)
			}
			for _, frame := range []struct {
				opcode  byte
				fin     bool
				payload string
			}{{0x2, true, "\x01hello "}, {0x2, false, "\x02wo"}, {0x0, true, "rld"}, {0x2, true, "\x01" + long}} {
				if err := peer.send(frame.opcode, frame.fin, []byte(frame.payload)); err != nil {
					return err
				}
			}
			for _, into := range []*[]byte{&got.input, &got.resize} {
				opcode, payload, err := peer.receive()
				if err != nil || opcode != 0x2 {
					return fmt.Errorf("client frame = %x %v", opcode, err)
				}
				*into = payload
			}
			status := `{"metadata":{},"status":"Failure","message":"command terminated with non-zero exit code: exit status 3","reason":"NonZeroExitCode",` +
				`"details":{"causes":[{"reason":"ExitCode","message":"3"}]}}`
			if err := peer.send(0x2, true, append([]byte{3}, status...)); err != nil {
				return err
			}
			opcode, _, err := peer.receive()
			got.closeOpcode = opcode
			return err
		}()
		if err != nil {
			failed <- err
			return
		}
		result <- got
	}()

	exec, err := openKubeExec(client, "team-a", "web-0", "app", []string{"sh", "-c", "echo hi"}, 100, 30)
	if err != nil {
		t.Fatal(err)
	}
	want := "hello world" + long
	var out bytes.Buffer
	buf := make([]byte, 64)
	for out.Len() < len(want) {
		n, err := exec.Read(buf)
		if err != nil {
			t.Fatalf("read after %q: %v", out.String(), err)
		}
		out.Write(buf[:n])
	}
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
	if _, err := exec.Write([]byte("ls\n")); err != nil {
		t.Fatal(err)
	}
	if err := exec.Resize(120, 40); err != nil {
		t.Fatal(err)
	}
	if n, err := exec.Read(buf); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read at the exec's end = %d %v", n, err)
	}
	select {
	case <-exec.Done():
	default:
		t.Fatal("the exec is not done after its final status")
	}
	if exec.ExitStatus() != 3 {
		t.Fatalf("exit status = %d, want 3", exec.ExitStatus())
	}
	if err := exec.Close(); err != nil {
		t.Fatal(err)
	}

	var got seen
	select {
	case err := <-failed:
		t.Fatal(err)
	case got = <-result:
	case <-time.After(10 * time.Second):
		t.Fatal("the gateway side did not finish")
	}
	if got.req.Method != http.MethodGet || got.req.URL.Path != "/api/v1/namespaces/team-a/pods/web-0/exec" {
		t.Fatalf("exec request = %s %s", got.req.Method, got.req.URL.Path)
	}
	query := got.req.URL.Query()
	if !reflect.DeepEqual(query["command"], []string{"sh", "-c", "echo hi"}) || query.Get("container") != "app" ||
		query.Get("stdin") != "true" || query.Get("stdout") != "true" || query.Get("stderr") != "true" || query.Get("tty") != "true" {
		t.Fatalf("exec query = %v", query)
	}
	key, err := base64.StdEncoding.DecodeString(got.req.Header.Get("Sec-WebSocket-Key"))
	if err != nil || len(key) != 16 || !strings.EqualFold(got.req.Header.Get("Upgrade"), "websocket") ||
		got.req.Header.Get("Sec-WebSocket-Protocol") != "v5.channel.k8s.io" || got.req.Header.Get("Sec-WebSocket-Version") != "13" ||
		got.req.Header.Get("Authorization") != "" {
		t.Fatalf("exec upgrade headers = %v", got.req.Header)
	}
	if string(got.input) != "\x00ls\n" {
		t.Fatalf("typed input frame = %q", got.input)
	}
	var size map[string]int
	if len(got.resize) == 0 || got.resize[0] != 4 || json.Unmarshal(got.resize[1:], &size) != nil || size["Width"] != 120 || size["Height"] != 40 {
		t.Fatalf("resize frame = %q", got.resize)
	}
	if got.closeOpcode != 0x8 {
		t.Fatalf("closing the exec sent opcode %x, want a close frame", got.closeOpcode)
	}
}

// TestKubeExecRefusalsA259: a refused upgrade, a masked or oversized server
// frame and a terminal size out of bounds end the exec, with no exit
// status.
func TestKubeExecRefusalsA259(t *testing.T) {
	if _, err := openKubeExec(nil, "ns", "pod", "", []string{"sh"}, 0, 30); err == nil {
		t.Fatal("a terminal with no columns was accepted")
	}
	run := func(answer string, frame func(kubeExecPeer) error) (*kubeExec, error) {
		t.Helper()
		client, server := net.Pipe()
		t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
		peer := kubeExecPeer{c: server, br: bufio.NewReader(server)}
		go func() {
			if _, err := peer.upgrade(answer); err == nil && frame != nil {
				_ = frame(peer)
			}
		}()
		return openKubeExec(client, "ns", "pod", "", []string{"sh"}, 80, 24)
	}
	if _, err := run("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", nil); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("a refused exec = %v", err)
	}
	if _, err := run("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", nil); err == nil {
		t.Fatal("an upgrade without the exec protocol was accepted")
	}
	for name, frame := range map[string]func(kubeExecPeer) error{
		"masked": func(p kubeExecPeer) error {
			_, err := p.c.Write([]byte{0x82, 0x80 | 2, 1, 2, 3, 4, 0x01 ^ 1, 'x' ^ 2})
			return err
		},
		"oversized": func(p kubeExecPeer) error {
			head := binary.BigEndian.AppendUint64([]byte{0x82, 127}, kubeExecMaxFrame+1)
			_, err := p.c.Write(head)
			return err
		},
	} {
		exec, err := run(kubeExecSwitched, frame)
		if err != nil {
			t.Fatalf("%s: upgrade: %v", name, err)
		}
		if _, err := exec.Read(make([]byte, 8)); err == nil || errors.Is(err, io.EOF) {
			t.Fatalf("%s frame read = %v, want a refusal", name, err)
		}
		if exec.ExitStatus() != -1 {
			t.Fatalf("%s frame: exit status = %d", name, exec.ExitStatus())
		}
	}
}

func TestKubeExitStatusA259(t *testing.T) {
	for payload, want := range map[string]int{
		`{"metadata":{},"status":"Success"}`: 0,
		`{"status":"Failure","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"127"}]}}`: 127,
		`{"status":"Failure","reason":"InternalError","message":"container not found"}`:                                -1,
		`not json`: -1,
	} {
		if got := kubeExitStatus([]byte(payload)); got != want {
			t.Fatalf("kubeExitStatus(%s) = %d, want %d", payload, got, want)
		}
	}
}

// TestListKubePodsReadsTheFirstPageA259L4: a pods list is the API server's
// first page of a namespace's pods, asked as GET with limit=500. Each pod
// comes with its phase and its containers in its spec's order, sorted by
// name. A name a terminal could not name is left out, a further page marks
// the list truncated, and a refusal or an answer that is not a PodList is the
// session's refusal.
func TestListKubePodsReadsTheFirstPageA259L4(t *testing.T) {
	answer := func(status int, body string) net.Conn {
		client, server := net.Pipe()
		go func() {
			defer func() { _ = server.Close() }()
			req, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				return
			}
			if req.Method != http.MethodGet || req.URL.Path != "/api/v1/namespaces/team-a/pods" || req.URL.Query().Get("limit") != "500" {
				status, body = http.StatusBadRequest, "{}"
			}
			_, _ = fmt.Fprintf(server, "HTTP/1.1 %d X\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", status, len(body), body)
		}()
		return client
	}
	list := `{"metadata":{"continue":"next-page"},"items":[` +
		`{"metadata":{"name":"web-2"},"spec":{"containers":[{"name":"app"},{"name":"proxy"}]},"status":{"phase":"Running"}},` +
		`{"metadata":{"name":"Bad_Name"},"spec":{"containers":[{"name":"x"}]}},` +
		`{"metadata":{"name":"batch-1"},"spec":{"containers":[{"name":"job"}]},"status":{"phase":"Succeeded"}}]}`
	got, err := listKubePods(answer(http.StatusOK, list), "team-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.Namespace != "team-a" || !got.Truncated || len(got.Pods) != 2 ||
		got.Pods[0].Name != "batch-1" || got.Pods[0].Phase != "Succeeded" || strings.Join(got.Pods[0].Containers, ",") != "job" ||
		got.Pods[1].Name != "web-2" || got.Pods[1].Phase != "Running" || strings.Join(got.Pods[1].Containers, ",") != "app,proxy" {
		t.Fatalf("pods = %+v", got)
	}
	for status, want := range map[int]string{
		http.StatusForbidden:           "may not list pods in team-a",
		http.StatusUnauthorized:        "may not list pods in team-a",
		http.StatusInternalServerError: "HTTP 500",
	} {
		if _, err := listKubePods(answer(status, `{"kind":"Status"}`), "team-a"); !errors.Is(err, api.ErrPAMRejected) || !strings.Contains(err.Error(), want) {
			t.Fatalf("HTTP %d = %v, want %q", status, err, want)
		}
	}
	if _, err := listKubePods(answer(http.StatusOK, "not json"), "team-a"); !errors.Is(err, api.ErrPAMRejected) || !strings.Contains(err.Error(), "not a PodList") {
		t.Fatalf("a non-PodList answer = %v", err)
	}
}
