// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

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
