// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

// TestRecordingIndexEntriesA269: the index is the recording's index frames
// only — pixels, input and stream bytes never appear — filtered by a
// case-insensitive query and bounded.
func TestRecordingIndexEntriesA269(t *testing.T) {
	frames := []json.RawMessage{
		json.RawMessage(`{"t":1,"c":1,"e":"index","kind":"desktop_started","v":"desktop-proof at 127.0.0.1:3389"}`),
		json.RawMessage(`{"t":2,"c":1,"e":"desktop","kind":"pixels","d":"iVBORw0KGgo="}`),
		json.RawMessage(`{"t":3,"c":1,"s":"in","d":"c2VjcmV0"}`),
		json.RawMessage(`{"t":4,"c":1,"e":"index","kind":"clipboard_refused","v":"to_target 24 bytes"}`),
		json.RawMessage(`{"t":5,"c":1,"e":"index","kind":"window_title","v":"Orders - xterm"}`),
		json.RawMessage(`{"t":6,"c":1,"e":"index"}`),
		json.RawMessage(`not json`),
		json.RawMessage(`{"t":7,"c":1,"e":"index","kind":"desktop_ended"}`),
	}
	all := recordingIndexEntries(frames, "", nil, 1000)
	if len(all) != 4 || all[0].Kind != "desktop_started" || all[3].Kind != "desktop_ended" || all[2].Text != "Orders - xterm" {
		t.Fatalf("index = %+v", all)
	}
	if found := recordingIndexEntries(frames, "ORDERS", nil, 1000); len(found) != 1 || found[0].Kind != "window_title" || found[0].AtMillis != 5 {
		t.Fatalf("a title search found %+v", found)
	}
	if found := recordingIndexEntries(frames, "clipboard", nil, 1000); len(found) != 1 || found[0].Text != "to_target 24 bytes" {
		t.Fatalf("a refusal search found %+v", found)
	}
	if found := recordingIndexEntries(frames, "c2VjcmV0", nil, 1000); len(found) != 0 {
		t.Fatalf("stream bytes reached the index: %+v", found)
	}
	if bounded := recordingIndexEntries(frames, "", []api.PAMRecordingIndexEntry{{Kind: "earlier"}}, 2); len(bounded) != 2 || bounded[1].Kind != "desktop_started" {
		t.Fatalf("the index exceeded its bound: %+v", bounded)
	}
}
