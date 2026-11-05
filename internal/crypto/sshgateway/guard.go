// SPDX-License-Identifier: BUSL-1.1
package sshgateway

import (
	"context"
	"encoding/binary"
	"slices"
	"sync"

	"golang.org/x/crypto/ssh"
)

const MaxExecCommandBytes = 64 << 10

// ExecCommand validates one SSH string without copying it. The result is borrowed
// from payload; the caller must not retain it. Trailing bytes are not accepted.
func ExecCommand(payload []byte) ([]byte, bool) {
	if len(payload) < 4 || len(payload) > MaxExecCommandBytes+4 || uint64(binary.BigEndian.Uint32(payload[:4]))+4 != uint64(len(payload)) {
		return nil, false
	}
	return payload[4:], true
}

// A separate bounded pump notices channel CLOSE during a human review. Input EOF
// is deliberately different: stock exec clients close stdin before exec finishes.
func forwardGuardedRequests(ctx context.Context, in <-chan *ssh.Request, up, down ssh.Channel, replying *sync.Mutex, guard *RequestGuard, seen func(*ssh.Request)) {
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	type heldRequest struct {
		request *ssh.Request
		release func()
	}
	pending := make(chan heldRequest, 16)
	go func() {
		defer close(pending)
		defer cancel()
		for req := range in {
			if len(req.Payload) > MaxExecCommandBytes+4 {
				_ = req.Reply(false, nil)
				_ = down.Close()
				return
			}
			release, ok := guard.Reserve(len(req.Payload))
			if !ok {
				_ = req.Reply(false, nil)
				clear(req.Payload)
				_ = down.Close()
				return
			}
			held := heldRequest{req, release}
			select {
			case pending <- held:
			case <-work.Done():
				release()
				clear(req.Payload)
				_ = req.Reply(false, nil)
			default:
				release()
				clear(req.Payload)
				_ = req.Reply(false, nil)
				_ = down.Close()
				return
			}
		}
	}()
	for held := range pending {
		req := held.request
		allowed := work.Err() == nil && slices.Contains(clientRequests, req.Type) && guard.Inspect(work, req.Type, req.Payload) && work.Err() == nil
		if !allowed {
			// Recording records a fixed refusal marker; the held command is not sent
			// to the target or represented as an executed request.
			seen(&ssh.Request{Type: "command-refused", Payload: []byte("gateway command guardrail refused this request")})
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			clear(req.Payload)
			held.release()
			continue
		}
		seen(req)
		replying.Lock()
		ok, err := up.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			_ = req.Reply(ok && err == nil, nil)
		}
		replying.Unlock()
		clear(req.Payload)
		held.release()
	}
}
