// SPDX-License-Identifier: MPL-2.0

package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const retainedBatchMessages = 128
const retainedBatchBytes = 1 << 20

var errRetainedBatchUnsupported = errors.New("events: direct batch protocol unavailable")

// A batch changes only transport. Every envelope still goes through the caller's
// decode, privacy preflight, identity checks and generation fence. No event or
// safety decision is cached between reads.
type retainedBatchStream struct {
	jetstream.Stream
	nc      *nats.Conn
	name    string
	prefix  string
	timeout time.Duration
}

func (l *Log) retainedTransport(stream jetstream.Stream, info *jetstream.StreamInfo) jetstream.Stream {
	if !info.Config.AllowDirect || l.nc == nil || l.nc.MaxPayload() <= 0 || l.nc.MaxPayload() > 32<<20 {
		return stream
	}
	opts := l.js.Options()
	prefix := opts.APIPrefix
	if opts.Domain != "" {
		prefix = "$JS." + opts.Domain + ".API."
	} else if prefix == "" {
		prefix = jetstream.DefaultAPIPrefix
	}
	prefix = strings.TrimSuffix(prefix, ".") + "."
	return retainedBatchStream{Stream: stream, nc: l.nc, name: info.Config.Name, prefix: prefix, timeout: opts.DefaultTimeout}
}

func (s retainedBatchStream) readRetainedRange(ctx context.Context, from, through uint64, visit func(*jetstream.RawStreamMsg) error) error {
	return s.readRetainedPages(ctx, from, through, func(page []*jetstream.RawStreamMsg) error {
		for _, raw := range page {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := visit(raw); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s retainedBatchStream) readRetainedPages(ctx context.Context, from, through uint64, visit func([]*jetstream.RawStreamMsg) error) error {
	for from <= through {
		page, last, complete, err := s.readBatch(ctx, from, through)
		if errors.Is(err, errRetainedBatchUnsupported) {
			// Older servers ignore batch fields and return the ordinary direct-get
			// grammar. No callback from this page has run; use the existing reader.
			return readRetainedThrough(ctx, s.Stream, from, through, func(raw *jetstream.RawStreamMsg) error {
				return visit([]*jetstream.RawStreamMsg{raw})
			})
		}
		if err != nil {
			return err
		}
		// A sparse batch can include a later physical sequence. Keep decoding
		// and callbacks inside the caller's finite cut, as the raw reader does.
		end := 0
		for end < len(page) && page[end].Sequence <= through {
			end++
		}
		if err := visit(page[:end]); err != nil {
			return err
		}
		if complete || last >= through {
			return ctx.Err()
		}
		if last < from {
			return errors.New("events: direct batch made no progress")
		}
		from = last + 1 // last < through, so this cannot wrap.
	}
	return ctx.Err()
}

func (s retainedBatchStream) readBatch(ctx context.Context, from, through uint64) (page []*jetstream.RawStreamMsg, last uint64, complete bool, err error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, false, err
	}
	count := retainedBatchMessages
	if remaining := through - from; remaining < retainedBatchMessages {
		count = int(remaining) + 1
	}
	request, err := json.Marshal(struct {
		Seq      uint64 `json:"seq"`
		Batch    int    `json:"batch"`
		MaxBytes int    `json:"max_bytes"`
	}{from, count, retainedBatchBytes})
	if err != nil {
		return nil, 0, false, err
	}
	requestCtx := ctx
	if _, set := ctx.Deadline(); !set {
		timeout := s.timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		var cancel context.CancelFunc
		requestCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	inbox := s.nc.NewInbox()
	// The server may send the final message that crosses max_bytes. Its own
	// max_payload bounds that overshoot; reserve header space and the EOB too.
	byteLimit := retainedBatchBytes + int(s.nc.MaxPayload()) + retainedBatchMessages*2048
	responses, err := subscribeRetainedInbox(requestCtx, s.nc, inbox, count+1, byteLimit)
	if err != nil {
		return nil, 0, false, err
	}
	defer func() { err = errors.Join(err, responses.close()) }()
	if err = s.nc.PublishRequest(s.prefix+"DIRECT.GET."+s.name, inbox, request); err != nil {
		return nil, 0, false, err
	}
	page = make([]*jetstream.RawStreamMsg, 0, count)
	var previousPending uint64
	bytesRead := 0
	for {
		msg, receiveErr := responses.next(requestCtx)
		if receiveErr != nil {
			return nil, 0, false, fmt.Errorf("events: receive retained batch: %w", receiveErr)
		}
		if len(msg.Header["Status"]) > 1 {
			return nil, 0, false, errors.New("events: ambiguous retained batch status")
		}
		if msg.Header.Get("Status") == "404" && len(page) == 0 && len(msg.Data) == 0 {
			// A server without batch support can mean only that the requested
			// first sequence was deleted. It does not prove the range is empty.
			return nil, 0, false, errRetainedBatchUnsupported
		}
		if msg.Header.Get("Status") == "204" {
			end, endErr := retainedUintHeader(msg.Header, "Nats-Last-Sequence")
			pending, pendingErr := retainedUintHeader(msg.Header, "Nats-Num-Pending")
			if endErr != nil || pendingErr != nil || len(msg.Data) != 0 || end != last || (len(page) == 0 && pending != 0) {
				return nil, 0, false, errors.New("events: incomplete retained batch trailer")
			}
			return page, last, pending == 0, nil
		}
		if msg.Header.Get("Status") != "" {
			return nil, 0, false, errors.New("events: retained batch was refused")
		}
		if len(page) == 0 && msg.Header.Get("Nats-Last-Sequence") == "" && msg.Header.Get("Nats-Num-Pending") == "" {
			legacySequence, legacyErr := retainedUintHeader(msg.Header, "Nats-Sequence")
			_, stampErr := time.Parse(time.RFC3339Nano, msg.Header.Get("Nats-Time-Stamp"))
			if legacyErr != nil || stampErr != nil || legacySequence != from ||
				msg.Header.Get("Nats-Stream") != s.name || msg.Header.Get("Nats-Subject") == "" {
				return nil, 0, false, errors.New("events: invalid legacy direct response")
			}
			return nil, 0, false, errRetainedBatchUnsupported
		}
		sequence, seqErr := retainedUintHeader(msg.Header, "Nats-Sequence")
		prior, priorErr := retainedUintHeader(msg.Header, "Nats-Last-Sequence")
		pending, pendingErr := retainedUintHeader(msg.Header, "Nats-Num-Pending")
		stamp, timeErr := time.Parse(time.RFC3339Nano, msg.Header.Get("Nats-Time-Stamp"))
		bytesRead += msg.Size()
		if seqErr != nil || priorErr != nil || pendingErr != nil || timeErr != nil ||
			msg.Header.Get("Nats-Stream") != s.name || msg.Header.Get("Nats-Subject") == "" ||
			sequence < from || sequence <= last || prior != last ||
			(len(page) > 0 && (previousPending == 0 || pending != previousPending-1)) ||
			len(page) >= count || bytesRead > byteLimit {
			return nil, 0, false, errors.New("events: retained batch identity, order or bounds differ")
		}
		page = append(page, &jetstream.RawStreamMsg{
			Subject: msg.Header.Get("Nats-Subject"), Sequence: sequence, Header: msg.Header,
			Data: msg.Data, Time: stamp,
		})
		last, previousPending = sequence, pending
	}
}

func retainedUintHeader(header nats.Header, name string) (uint64, error) {
	values := header[name]
	if len(values) != 1 || values[0] == "" {
		return 0, errors.New("events: missing or ambiguous retained batch header")
	}
	return strconv.ParseUint(values[0], 10, 64)
}
