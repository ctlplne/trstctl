// Package problem implements RFC 7807 "Problem Details for HTTP APIs": the
// application/problem+json error representation used across trstctl's API.
//
// Standard members (type, title, status, detail, instance) are typed fields;
// any additional ("extension") members live in Extensions and are marshaled as
// siblings of the standard members, so a value round-trips through JSON.
package problem

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// MediaType is the RFC 7807 content type.
const MediaType = "application/problem+json"

// Problem is an RFC 7807 problem details object.
type Problem struct {
	Type       string
	Title      string
	Status     int
	Detail     string
	Instance   string
	Extensions map[string]any
}

// reserved holds the standard member names, which extensions may not shadow.
var reserved = map[string]struct{}{
	"type": {}, "title": {}, "status": {}, "detail": {}, "instance": {},
}

// New returns a Problem for the given HTTP status. The title defaults to the
// standard reason phrase for the status; detail is optional.
func New(status int, detail string) *Problem {
	return &Problem{
		Status: status,
		Title:  http.StatusText(status),
		Detail: detail,
	}
}

// WithType sets the problem type URI and returns the problem for chaining.
func (p *Problem) WithType(uri string) *Problem { p.Type = uri; return p }

// WithTitle overrides the title.
func (p *Problem) WithTitle(title string) *Problem { p.Title = title; return p }

// WithDetail sets the human-readable detail.
func (p *Problem) WithDetail(detail string) *Problem { p.Detail = detail; return p }

// WithInstance sets the instance URI reference.
func (p *Problem) WithInstance(uri string) *Problem { p.Instance = uri; return p }

// WithExtension sets an extension member. Reserved (standard) names are ignored
// so an extension can never shadow a standard member.
func (p *Problem) WithExtension(key string, value any) *Problem {
	if _, isReserved := reserved[key]; isReserved {
		return p
	}
	if p.Extensions == nil {
		p.Extensions = make(map[string]any)
	}
	p.Extensions[key] = value
	return p
}

// Error implements error so a Problem can be propagated as one.
func (p *Problem) Error() string {
	if p.Detail != "" {
		return fmt.Sprintf("%d %s: %s", p.Status, p.Title, p.Detail)
	}
	return fmt.Sprintf("%d %s", p.Status, p.Title)
}

// Write sends the problem as an application/problem+json response using the
// problem's status code (defaulting to 500 if unset).
func (p *Problem) Write(w http.ResponseWriter) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", MediaType)
	status := p.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	w.WriteHeader(status)
	_, err = w.Write(body)
	return err
}

// MarshalJSON renders the problem as a single JSON object with the standard
// members plus any extensions as siblings. A missing type defaults to
// "about:blank" per RFC 7807.
func (p *Problem) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(p.Extensions)+5)
	for k, v := range p.Extensions {
		if _, isReserved := reserved[k]; !isReserved {
			m[k] = v
		}
	}
	if p.Type != "" {
		m["type"] = p.Type
	} else {
		m["type"] = "about:blank"
	}
	if p.Title != "" {
		m["title"] = p.Title
	}
	if p.Status != 0 {
		m["status"] = p.Status
	}
	if p.Detail != "" {
		m["detail"] = p.Detail
	}
	if p.Instance != "" {
		m["instance"] = p.Instance
	}
	return json.Marshal(m)
}

// UnmarshalJSON parses an RFC 7807 object, routing unknown members into
// Extensions so a value round-trips.
func (p *Problem) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*p = Problem{}
	if err := extractString(raw, "type", &p.Type); err != nil {
		return err
	}
	if err := extractString(raw, "title", &p.Title); err != nil {
		return err
	}
	if v, ok := raw["status"]; ok {
		if err := json.Unmarshal(v, &p.Status); err != nil {
			return err
		}
		delete(raw, "status")
	}
	if err := extractString(raw, "detail", &p.Detail); err != nil {
		return err
	}
	if err := extractString(raw, "instance", &p.Instance); err != nil {
		return err
	}
	if len(raw) > 0 {
		p.Extensions = make(map[string]any, len(raw))
		for k, v := range raw {
			var val any
			if err := json.Unmarshal(v, &val); err != nil {
				return err
			}
			p.Extensions[k] = val
		}
	}
	return nil
}

func extractString(raw map[string]json.RawMessage, key string, dst *string) error {
	v, ok := raw[key]
	if !ok {
		return nil
	}
	if err := json.Unmarshal(v, dst); err != nil {
		return err
	}
	delete(raw, key)
	return nil
}
