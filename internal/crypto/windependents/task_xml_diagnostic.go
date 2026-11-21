// SPDX-License-Identifier: BUSL-1.1

package windependents

import (
	"crypto/sha256"
	"fmt"
)

// taskXMLSegment keeps only a safe XML tag name and a digest of one UTF-16
// segment. Task actions may contain credentials, so no XML value or raw bytes
// survive the native BSTR lease or appear in a diagnostic.
type taskXMLSegment struct {
	tag    string
	digest [32]byte
	bytes  int
}

func taskXMLSegments(raw []byte) []taskXMLSegment {
	const maxSegments = 512
	var segments []taskXMLSegment
	for start := 0; start+1 < len(raw) && len(segments) < maxSegments; start += 2 {
		if raw[start] != '<' || raw[start+1] != 0 {
			continue
		}
		end := start + 2
		for end+1 < len(raw) && (raw[end] != '<' || raw[end+1] != 0) {
			end += 2
		}
		name := make([]byte, 0, 48)
		for pos := start + 2; pos+1 < end && len(name) < 64; pos += 2 {
			if raw[pos+1] != 0 {
				break
			}
			ch := raw[pos]
			if ch == '/' && len(name) == 0 {
				name = append(name, ch)
				continue
			}
			if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
				(ch >= '0' && ch <= '9') || ch == ':' || ch == '_' || ch == '-' || ch == '.') {
				break
			}
			name = append(name, ch)
		}
		if len(name) > 0 {
			segments = append(segments, taskXMLSegment{tag: string(name), digest: sha256.Sum256(raw[start:end]), bytes: end - start})
		}
		start = end - 2
	}
	return segments
}

func firstTaskXMLDifference(before, after []taskXMLSegment) string {
	count := min(len(before), len(after))
	for i := range count {
		if before[i].digest != after[i].digest {
			return fmt.Sprintf("segment=%d before_tag=%s after_tag=%s bytes=%d/%d segments=%d/%d",
				i, before[i].tag, after[i].tag, before[i].bytes, after[i].bytes, len(before), len(after))
		}
	}
	if len(before) != len(after) {
		return fmt.Sprintf("segment=%d segments=%d/%d", count, len(before), len(after))
	}
	return "same segments"
}
