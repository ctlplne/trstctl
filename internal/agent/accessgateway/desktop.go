// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"net"
	"strings"

	"trstctl.com/trstctl/internal/agent/desktop"
	"trstctl.com/trstctl/internal/crypto/rdp"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func serveDesktop(parent context.Context, client net.Conn, raw []byte, intent SessionIntent, helper string, rec *connRecorder) error {
	if intent.Desktop == nil || intent.Desktop.Validate() != nil {
		return errors.New("accessgateway: desktop route unavailable")
	}
	defer secret.Wipe(raw)
	username, held, err := parseDesktopCredential(raw)
	secret.Wipe(raw)
	if err != nil {
		return err
	}
	defer held.Destroy()
	ctx, cancel := context.WithDeadline(parent, intent.ExpiresAt)
	defer cancel()
	binding := *intent.Desktop
	target := rdp.Target{Address: binding.Address, Username: username, Domain: binding.Domain, CertificateSHA256: binding.CertificateSHA256, Width: binding.Width, Height: binding.Height, TLSOnly: binding.TLSOnly}
	var backend *rdp.Stream
	err = held.Use(func(password []byte) error {
		var e error
		backend, e = rdp.Start(ctx, helper, target, password)
		return e
	})
	if err != nil {
		return err
	}
	// The native child has received its private locked request. Do not retain a
	// second copy for the lifetime of the interactive desktop.
	held.Destroy()
	return desktop.Serve(ctx, client, backend, func(ctx context.Context, p rdp.Packet) error {
		if rec == nil {
			return nil
		}
		return rec.desktop(ctx, p)
	})
}

// desktopTile is a bounded replay unit. Data is a lossless PNG tile, not
// text; regex masking must never corrupt or inspect binary image bytes.
type desktopTile struct {
	Codec  string `json:"codec"`
	Frame  uint64 `json:"frame"`
	Width  uint16 `json:"width"`
	Height uint16 `json:"height"`
	Y      uint16 `json:"y"`
	Rows   uint16 `json:"rows"`
	Last   bool   `json:"last"`
}

func (c *connRecorder) desktop(ctx context.Context, p rdp.Packet) error {
	if p.Kind != 2 || p.Width < 320 || p.Width > 1280 || p.Height < 200 || p.Height > 1024 || len(p.Pixels) != int(p.Width)*int(p.Height)*4 {
		return errors.New("accessgateway: invalid desktop pixels")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.desktopFrame++
	for y := 0; y < int(p.Height); y += 16 {
		rows := min(16, int(p.Height)-y)
		start := y * int(p.Width) * 4
		end := start + rows*int(p.Width)*4
		img := image.NewNRGBA(image.Rect(0, 0, int(p.Width), rows))
		source := p.Pixels[start:end]
		for i := 0; i < len(source); i += 4 {
			img.Pix[i] = source[i+2]
			img.Pix[i+1] = source[i+1]
			img.Pix[i+2] = source[i]
			img.Pix[i+3] = 255
		}
		var encoded bytes.Buffer
		encoder := png.Encoder{CompressionLevel: png.BestSpeed}
		if err := encoder.Encode(&encoded, img); err != nil {
			return err
		}
		tile := desktopTile{Codec: "png", Frame: c.desktopFrame, Width: p.Width, Height: p.Height, Y: uint16(y), Rows: uint16(rows & 65535), Last: y+rows == int(p.Height)}
		if err := c.r.writeContext(ctx, frame{Conn: c.conn, Event: "desktop", Kind: "pixels", Desktop: &tile, Data: base64.StdEncoding.EncodeToString(encoded.Bytes())}); err != nil {
			return err
		}
	}
	return nil
}

// writeContext is the cancellable pixel path. Tile lines fit the existing spool;
// a slow object store applies backpressure before pixels reach the viewer.
func (r *sessionRecorder) writeContext(ctx context.Context, f frame) error {
	f.T = r.now().Sub(r.start).Milliseconds()
	line, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(line)+1 > recordingSpool {
		return errors.New("accessgateway: recording tile exceeds spool capacity")
	}
	stopWake := context.AfterFunc(ctx, func() { r.mu.Lock(); r.cond.Broadcast(); r.mu.Unlock() })
	defer stopWake()
	r.mu.Lock()
	defer r.mu.Unlock()
	for r.spool.Len()+len(line)+1 > recordingSpool && !r.stopped && !r.closing && ctx.Err() == nil {
		r.cond.Wait()
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if r.stopped || r.closing {
		return ErrRecordingStopped
	}
	_, _ = r.spool.Write(line)
	_ = r.spool.WriteByte('\n')
	if r.spool.Len() >= recordingChunk {
		r.cond.Broadcast()
	}
	return nil
}

func parseDesktopCredential(raw []byte) (string, *secret.Buffer, error) {
	var c struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	defer func() { secret.Wipe(c.Password) }()
	if len(raw) > 64<<10 || json.Unmarshal(raw, &c) != nil || c.Username == "" || len(c.Username) > 128 || strings.ContainsAny(c.Username, "\x00\r\n") || len(c.Password) == 0 || len(c.Password) > 1024 || bytes.IndexByte(c.Password, 0) >= 0 {
		return "", nil, errors.New("accessgateway: invalid vaulted desktop credential")
	}
	held, err := secret.NewFrom(c.Password)
	return c.Username, held, err
}
