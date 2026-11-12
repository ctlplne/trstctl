// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
)

// A259 part 3: Kubernetes exec in the browser. For a Kubernetes session the
// control plane speaks HTTP to the session's gateway on the admitted
// connection (the gateway adds the session's token and forwards to the API
// server, recording the stream) and upgrades it to the exec WebSocket
// (v5.channel.k8s.io): channel 0 is the terminal's input, 1 and 2 its
// output, 3 the exec's final status, 4 a resize, 255 a close of the input.
// The control plane is only the client: it never holds the session's token.

const kubeExecMaxFrame = 1 << 20

// kubeExec is an exec stream through a Kubernetes session's gateway; it
// serves a browser terminal as an SSH shell does.
type kubeExec struct {
	conn net.Conn
	br   *bufio.Reader
	wmu  sync.Mutex
	rmu  sync.Mutex
	// pending holds output read from a frame that did not fit the reader.
	pending []byte
	done    chan struct{}
	once    sync.Once
	exit    int
}

// openKubeExec upgrades the admitted connection to an exec of command in the
// pod's container with a terminal of cols x rows.
func openKubeExec(conn net.Conn, namespace, pod, container string, command []string, cols, rows int) (*kubeExec, error) {
	if cols < 1 || rows < 1 || cols > 1000 || rows > 1000 {
		return nil, errors.New("terminal size must be 1-1000 columns and rows")
	}
	query := url.Values{"stdin": {"true"}, "stdout": {"true"}, "stderr": {"true"}, "tty": {"true"}}
	for _, arg := range command {
		query.Add("command", arg)
	}
	if container != "" {
		query.Set("container", container)
	}
	key, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(pod) + "/exec?" + query.Encode()
	request := "GET " + path + " HTTP/1.1\r\nHost: trstctl-gateway\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key) + "\r\n" +
		"Sec-WebSocket-Protocol: v5.channel.k8s.io\r\n\r\n"
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(conn, request); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("the exec upgrade: %w", err)
	}
	_ = resp.Body.Close()
	// The connection is the gateway's, verified by its agent identity; the
	// switch to the exec stream is read from the status and protocol.
	if resp.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		resp.Header.Get("Sec-WebSocket-Protocol") != "v5.channel.k8s.io" {
		return nil, fmt.Errorf("the cluster refused the exec: HTTP %d", resp.StatusCode)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return &kubeExec{conn: conn, br: br, done: make(chan struct{}), exit: -1}, nil
}

// Read returns the exec's output (channels 1 and 2) until it ends.
func (k *kubeExec) Read(p []byte) (int, error) {
	k.rmu.Lock()
	defer k.rmu.Unlock()
	for len(k.pending) == 0 {
		channel, payload, err := k.readMessage()
		if err != nil {
			k.finish(-1)
			return 0, err
		}
		switch channel {
		case 1, 2:
			k.pending = payload
		case 3:
			k.finish(kubeExitStatus(payload))
			return 0, io.EOF
		}
	}
	n := copy(p, k.pending)
	k.pending = k.pending[n:]
	return n, nil
}

// readMessage reads one data message, answering pings, and returns its
// channel byte and payload.
func (k *kubeExec) readMessage() (byte, []byte, error) {
	var message []byte
	for {
		head := make([]byte, 2)
		if _, err := io.ReadFull(k.br, head); err != nil {
			return 0, nil, err
		}
		fin, opcode, masked := head[0]&0x80 != 0, head[0]&0x0f, head[1]&0x80 != 0
		length := uint64(head[1] & 0x7f)
		switch length {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(k.br, ext[:]); err != nil {
				return 0, nil, err
			}
			length = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(k.br, ext[:]); err != nil {
				return 0, nil, err
			}
			length = binary.BigEndian.Uint64(ext[:])
		}
		if masked || length > kubeExecMaxFrame || uint64(len(message))+length > kubeExecMaxFrame {
			return 0, nil, errors.New("the exec stream sent a frame this client does not accept")
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(k.br, payload); err != nil {
			return 0, nil, err
		}
		switch opcode {
		case 0x8: // close
			return 0, nil, io.EOF
		case 0x9: // ping
			if err := k.writeFrame(0xA, payload); err != nil {
				return 0, nil, err
			}
			continue
		case 0xA: // pong
			continue
		case 0x0, 0x1, 0x2:
			message = append(message, payload...)
		default:
			return 0, nil, errors.New("the exec stream sent an unknown frame")
		}
		if fin {
			break
		}
	}
	if len(message) == 0 {
		return 0, nil, errors.New("the exec stream sent an empty message")
	}
	return message[0], message[1:], nil
}

// writeFrame sends one masked binary (or control) frame, as a client must.
func (k *kubeExec) writeFrame(opcode byte, payload []byte) error {
	mask, err := crypto.RandomBytes(4)
	if err != nil {
		return err
	}
	frame := []byte{0x80 | opcode}
	switch n := len(payload); {
	case n < 126:
		frame = append(frame, 0x80|byte(n)) // #nosec G115 -- a 7-bit length below 126 (CWE-190)
	case n < 1<<16:
		frame = append(frame, 0x80|126)
		frame = binary.BigEndian.AppendUint16(frame, uint16(n)) // #nosec G115 -- a 16-bit length under 1<<16 (CWE-190)
	default:
		frame = append(frame, 0x80|127)
		frame = binary.BigEndian.AppendUint64(frame, uint64(n)) // #nosec G115 -- a payload length, never negative (CWE-190)
	}
	frame = append(frame, mask...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%4])
	}
	k.wmu.Lock()
	defer k.wmu.Unlock()
	_, err = k.conn.Write(frame)
	return err
}

// Write types into the exec's terminal (channel 0).
func (k *kubeExec) Write(p []byte) (int, error) {
	if err := k.writeFrame(0x2, append([]byte{0}, p...)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Resize changes the exec terminal's size (channel 4).
func (k *kubeExec) Resize(cols, rows int) error {
	if cols < 1 || rows < 1 || cols > 1000 || rows > 1000 {
		return errors.New("terminal size must be 1-1000 columns and rows")
	}
	size, _ := json.Marshal(map[string]int{"Width": cols, "Height": rows})
	return k.writeFrame(0x2, append([]byte{4}, size...))
}

func (k *kubeExec) finish(exit int) {
	k.once.Do(func() {
		k.exit = exit
		close(k.done)
	})
}

// Done is closed when the exec ends.
func (k *kubeExec) Done() <-chan struct{} { return k.done }

// ExitStatus is the exec's exit status once Done is closed, or -1.
func (k *kubeExec) ExitStatus() int { return k.exit }

// Close ends the exec and its connection.
func (k *kubeExec) Close() error {
	_ = k.writeFrame(0x8, nil)
	k.finish(-1)
	return k.conn.Close()
}

// kubeExitStatus reads the exit status from the exec's final status message.
func kubeExitStatus(payload []byte) int {
	var status struct {
		Status  string `json:"status"`
		Details struct {
			Causes []struct {
				Reason  string `json:"reason"`
				Message string `json:"message"`
			} `json:"causes"`
		} `json:"details"`
	}
	if json.Unmarshal(payload, &status) != nil {
		return -1
	}
	if status.Status == "Success" {
		return 0
	}
	for _, cause := range status.Details.Causes {
		if cause.Reason == "ExitCode" {
			if code, err := strconv.Atoi(cause.Message); err == nil {
				return code
			}
		}
	}
	return -1
}

// A pods list (A259-L4) is the API server's first page of up to 500 pods,
// read from at most 8 MiB of its answer.
const (
	kubePodListLimit = 500
	kubePodListBytes = 8 << 20
)

// ListPAMSessionPods lists the pods a Kubernetes session opened for the
// browser can see in a namespace — its provider's when none is named — with
// each pod's containers, for its opener to choose a terminal's pod and
// container from (A259-L4). The control plane asks through the session's
// gateway, as a stock kubectl get pods would: the gateway adds the session's
// own token, forwards to the API server and records the exchange, so the
// cluster answers only what the session's account may list, and the control
// plane never holds the token.
func (s *pamService) ListPAMSessionPods(ctx context.Context, tenantID, sessionID, principal, namespace string) (api.PAMSessionPods, error) {
	rec, err := s.store.GetPAMSession(ctx, tenantID, sessionID)
	if err != nil {
		return api.PAMSessionPods{}, err
	}
	if rec.TargetType != pamTargetK8s || rec.Delivery != "gateway" || rec.Status != api.PAMSessionStatusActive || !s.clock().Before(rec.ExpiresAt) {
		return api.PAMSessionPods{}, fmt.Errorf("%w: pods are listed on an active Kubernetes session through a gateway", api.ErrPAMRejected)
	}
	if namespace == "" {
		namespace = s.kubernetesSessionNamespace(ctx, tenantID, rec.TargetID)
	}
	if !kubeName.MatchString(namespace) {
		return api.PAMSessionPods{}, fmt.Errorf("%w: a namespace is a Kubernetes object name", api.ErrPAMInvalid)
	}
	s.browser.mu.Lock()
	held := s.browser.tickets[pamBrowserKey{tenantID, sessionID}]
	s.browser.mu.Unlock()
	switch {
	case held == nil:
		return api.PAMSessionPods{}, fmt.Errorf("%w: the session was not opened for the browser", api.ErrPAMRejected)
	case held.opener != principal:
		return api.PAMSessionPods{}, fmt.Errorf("%w: only the person who opened the session can use it in the browser", api.ErrPAMRejected)
	}
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := s.browser.dial(dctx, held.address, held.caPEM, held.spiffeID)
	if err != nil {
		return api.PAMSessionPods{}, fmt.Errorf("%w: the session's gateway: %v", api.ErrPAMRejected, err)
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(dctx, func() { _ = conn.Close() })
	defer stop()
	if _, err := admitAtGateway(conn, sessionID, held.ticket); err != nil {
		return api.PAMSessionPods{}, fmt.Errorf("%w: %v", api.ErrPAMRejected, err)
	}
	return listKubePods(conn, namespace)
}

// kubernetesSessionNamespace is the namespace a Kubernetes target's provider
// scopes its sessions to.
func (s *pamService) kubernetesSessionNamespace(ctx context.Context, tenantID, targetID string) string {
	target, err := s.databaseTarget(ctx, tenantID, pamTargetK8s, targetID)
	if err != nil {
		return "default"
	}
	for _, provider := range s.providers.ForTenant(tenantID) {
		if provider == nil || provider.Name() != target.cfg.ProviderID {
			continue
		}
		if scoped, ok := provider.(interface {
			DynamicSecretKubernetesScope() (string, string)
		}); ok {
			namespace, _ := scoped.DynamicSecretKubernetesScope()
			return namespace
		}
	}
	return "default"
}

// listKubePods asks the API server, on a connection the gateway admitted, for
// the first page of a namespace's pods.
func listKubePods(conn net.Conn, namespace string) (api.PAMSessionPods, error) {
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return api.PAMSessionPods{}, err
	}
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods?limit=" + strconv.Itoa(kubePodListLimit)
	if _, err := io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: trstctl-gateway\r\nAccept: application/json\r\nConnection: close\r\n\r\n"); err != nil {
		return api.PAMSessionPods{}, fmt.Errorf("%w: the pods list: %v", api.ErrPAMRejected, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return api.PAMSessionPods{}, fmt.Errorf("%w: the pods list: %v", api.ErrPAMRejected, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, kubePodListBytes+1))
	if err != nil {
		return api.PAMSessionPods{}, fmt.Errorf("%w: the pods list: %v", api.ErrPAMRejected, err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return api.PAMSessionPods{}, fmt.Errorf("%w: the session's account may not list pods in %s", api.ErrPAMRejected, namespace)
	case resp.StatusCode != http.StatusOK:
		return api.PAMSessionPods{}, fmt.Errorf("%w: the cluster refused the pods list: HTTP %d", api.ErrPAMRejected, resp.StatusCode)
	case len(body) > kubePodListBytes:
		return api.PAMSessionPods{}, fmt.Errorf("%w: the cluster's pods list is larger than 8 MiB", api.ErrPAMRejected)
	}
	var list struct {
		Metadata struct {
			Continue string `json:"continue"`
		} `json:"metadata"`
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				Containers []struct {
					Name string `json:"name"`
				} `json:"containers"`
			} `json:"spec"`
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return api.PAMSessionPods{}, fmt.Errorf("%w: the cluster's pods list is not a PodList", api.ErrPAMRejected)
	}
	out := api.PAMSessionPods{Namespace: namespace, Pods: make([]api.PAMSessionPod, 0, len(list.Items)), Truncated: list.Metadata.Continue != ""}
	for _, item := range list.Items {
		// Only a name a terminal may name is offered.
		if !kubeName.MatchString(item.Metadata.Name) {
			continue
		}
		pod := api.PAMSessionPod{Name: item.Metadata.Name, Phase: item.Status.Phase, Containers: make([]string, 0, len(item.Spec.Containers))}
		for _, container := range item.Spec.Containers {
			if kubeName.MatchString(container.Name) {
				pod.Containers = append(pod.Containers, container.Name)
			}
		}
		out.Pods = append(out.Pods, pod)
	}
	sort.Slice(out.Pods, func(i, j int) bool { return out.Pods[i].Name < out.Pods[j].Name })
	return out, nil
}
