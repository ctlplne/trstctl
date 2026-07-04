// SPDX-License-Identifier: MPL-2.0

// Package scim implements the SCIM 2.0 wire types trstctl serves for directory
// provisioning. It is pure: HTTP handlers map these types onto tenant-member
// events, but the schema objects themselves have no datastore dependency.
package scim

import "time"

const ContentType = "application/scim+json"

const (
	SchemaUser     = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup    = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaList     = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaPatchOp  = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaError    = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaSPConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
)

type Meta struct {
	ResourceType string     `json:"resourceType"`
	Created      *time.Time `json:"created,omitempty"`
	LastModified *time.Time `json:"lastModified,omitempty"`
	Location     string     `json:"location,omitempty"`
}

type Name struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type Email struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

type User struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	UserName    string   `json:"userName"`
	Name        *Name    `json:"name,omitempty"`
	DisplayName string   `json:"displayName,omitempty"`
	Emails      []Email  `json:"emails,omitempty"`
	Active      bool     `json:"active"`
	Meta        *Meta    `json:"meta,omitempty"`
}

func (u User) PrimaryEmail() string {
	for _, e := range u.Emails {
		if e.Primary {
			return e.Value
		}
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return ""
}

type Member struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

type Group struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []Member `json:"members,omitempty"`
	Meta        *Meta    `json:"meta,omitempty"`
}

type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

func NewList(resources []any, total, startIndex, perPage int) ListResponse {
	if resources == nil {
		resources = []any{}
	}
	return ListResponse{
		Schemas:      []string{SchemaList},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: perPage,
		Resources:    resources,
	}
}

type Error struct {
	Schemas  []string `json:"schemas"`
	Detail   string   `json:"detail"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
}

func NewError(httpStatus int, scimType, detail string) Error {
	return Error{Schemas: []string{SchemaError}, Detail: detail, Status: itoa(httpStatus), ScimType: scimType}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
