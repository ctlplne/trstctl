// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"sync"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/rdp"
)

func TestDesktopRecordingTilesAreLosslessBoundedAndCancellable(t *testing.T) {
	r := &sessionRecorder{start: time.Now(), now: time.Now}
	r.cond = sync.NewCond(&r.mu)
	c := &connRecorder{r: r, conn: 1}
	pixels := make([]byte, 320*200*4)
	for i := 0; i < len(pixels); i += 4 {
		pixels[i] = 128
	}
	if err := c.desktop(context.Background(), rdp.Packet{Kind: 2, Width: 320, Height: 200, Pixels: pixels}); err != nil {
		t.Fatal(err)
	}
	if r.spool.Len() > len(pixels)/4 {
		t.Fatal("static desktop recording did not compress")
	}
	scanner := bufio.NewScanner(bytes.NewReader(r.spool.Bytes()))
	scanner.Buffer(make([]byte, 4096), recordingChunk)
	rows := 0
	for scanner.Scan() {
		var f frame
		if err := json.Unmarshal(scanner.Bytes(), &f); err != nil {
			t.Fatal(err)
		}
		if f.Desktop == nil || f.Desktop.Codec != "png" || int(f.Desktop.Y) != rows || f.Desktop.Rows > 16 {
			t.Fatal("invalid replay tile metadata")
		}
		raw, e := base64.StdEncoding.DecodeString(f.Data)
		if e != nil {
			t.Fatal(e)
		}
		config, e := png.DecodeConfig(bytes.NewReader(raw))
		if e != nil || config.Width != 320 || config.Height != int(f.Desktop.Rows) {
			t.Fatal("unbounded PNG tile")
		}
		img, e := png.Decode(bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		red, green, blue, alpha := img.At(0, 0).RGBA()
		if red != 0 || green != 0 || blue != 32896 || alpha != 65535 {
			t.Fatal("desktop pixel color changed")
		}
		rows += int(f.Desktop.Rows)
	}
	if e := scanner.Err(); e != nil {
		t.Fatal(e)
	}
	if rows != 200 {
		t.Fatal("desktop rows lost")
	}
	before := r.spool.Len()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c.desktop(ctx, rdp.Packet{Kind: 2, Width: 320, Height: 200, Pixels: pixels}) == nil || r.spool.Len() != before {
		t.Fatal("cancelled recording accepted more pixels")
	}
	if c.desktop(context.Background(), rdp.Packet{Kind: 2, Width: 1281, Height: 200}) == nil {
		t.Fatal("invalid bitmap accepted")
	}
}

func FuzzDesktopCredential(f *testing.F) {
	f.Add([]byte(`{"username":"account","password":"x"}`))
	f.Add([]byte(`{"username":"other","password":"\u0000"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		user, held, err := parseDesktopCredential(raw)
		if err != nil {
			if held != nil {
				held.Destroy()
			}
			return
		}
		defer held.Destroy()
		if user == "" || len(user) > 128 || held.Len() < 1 || held.Len() > 1024 {
			t.Fatal("unbounded desktop credential")
		}
	})
}
