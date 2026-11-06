// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"unicode/utf16"
)

func parsePoolWorkerMetadata(raw []byte, name string) ([]uint32, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || !validPoolName(name) {
		return nil, errors.New("windows pool: invalid bounded worker metadata")
	}
	if len(raw) >= 2 && raw[0] == 0xff && raw[1] == 0xfe {
		if len(raw)%2 != 0 {
			return nil, errors.New("windows pool: malformed Unicode worker metadata")
		}
		units := make([]uint16, (len(raw)-2)/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(raw[2+i*2:])
		}
		for i := 0; i < len(units); i++ {
			unit := units[i]
			if unit >= 0xd800 && unit <= 0xdbff {
				if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
					return nil, errors.New("windows pool: malformed Unicode surrogate")
				}
				i++
			} else if unit >= 0xdc00 && unit <= 0xdfff {
				return nil, errors.New("windows pool: malformed Unicode surrogate")
			}
		}
		raw = []byte(string(utf16.Decode(units)))
		raw = bytes.Replace(raw, []byte("encoding=\"UTF-16\""), []byte("encoding=\"UTF-8\""), 1)
	}
	raw = bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	depth := 0
	root := false
	closed := false
	seen := map[uint32]bool{}
	var found []uint32
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("windows pool: malformed native worker XML")
		}
		switch value := token.(type) {
		case xml.StartElement:
			if closed {
				return nil, errors.New("windows pool: multiple native worker roots")
			}
			depth++
			if depth == 1 {
				if root || value.Name.Space != "" || value.Name.Local != "appcmd" {
					return nil, errors.New("windows pool: unexpected native worker root")
				}
				root = true
				continue
			}
			if depth != 2 || value.Name.Space != "" || value.Name.Local != "WP" {
				return nil, errors.New("windows pool: unexpected nested native worker metadata")
			}
			pool, pidText := "", ""
			poolSeen, pidSeen := false, false
			for _, attribute := range value.Attr {
				if attribute.Name.Space != "" && (attribute.Name.Local == "APPPOOL.NAME" || attribute.Name.Local == "WP.NAME") {
					return nil, errors.New("windows pool: namespaced worker identity")
				}
				switch attribute.Name.Local {
				case "APPPOOL.NAME":
					if poolSeen {
						return nil, errors.New("windows pool: duplicate worker pool identity")
					}
					pool = attribute.Value
					poolSeen = true
				case "WP.NAME":
					if pidSeen {
						return nil, errors.New("windows pool: duplicate worker process identity")
					}
					pidText = attribute.Value
					pidSeen = true
				}
			}
			pid, err := strconv.ParseUint(pidText, 10, 32)
			if err != nil || pid == 0 || strconv.FormatUint(pid, 10) != pidText || pool != name || !poolSeen {
				return nil, errors.New("windows pool: foreign or invalid worker identity")
			}
			id := uint32(pid & 0xffffffff)
			if seen[id] || len(found) >= 128 {
				return nil, errors.New("windows pool: duplicate or unbounded worker set")
			}
			seen[id] = true
			found = append(found, id)
		case xml.EndElement:
			depth--
			if depth == 0 {
				closed = true
			}
			if depth < 0 {
				return nil, errors.New("windows pool: malformed worker depth")
			}
		case xml.CharData:
			if len(bytes.TrimSpace(value)) != 0 {
				return nil, errors.New("windows pool: unexpected worker text")
			}
		case xml.Directive:
			return nil, errors.New("windows pool: worker XML directives are forbidden")
		}
	}
	if !root || !closed || depth != 0 {
		return nil, errors.New("windows pool: incomplete worker metadata")
	}
	return found, nil
}
