// SPDX-License-Identifier: BUSL-1.1

package api

import "trstctl.com/trstctl/internal/authz"

// observerRoutes is the external observer surface (A180): an operator
// registers observers that receive rotation and rollback events, and an
// observer reports what it saw at endpoints with a discovery-scoped token.
func (a *API) observerRoutes(idPath []param) []route {
	observationQuery := []param{
		{name: "observer_id", typ: "string", format: "uuid", desc: "return only this observer's observations"},
		{name: "endpoint", typ: "string", desc: "return only observations of this host:port"},
		{name: "fingerprint", typ: "string", desc: "return only observations that served or expected this certificate SHA-256 fingerprint"},
		{name: "limit", typ: "integer", desc: "maximum items (1-500, default 500), newest first"},
	}
	return []route{
		{method: "POST", path: "/api/v1/observers", opID: "registerObserver", summary: "Register an external observer that reports what endpoints serve and receives rotation and rollback events", handler: a.registerObserver, reqSchema: "ObserverRequest", resSchema: "Observer", successCode: "201", mutation: true, perm: authz.NotificationsWrite},
		{method: "GET", path: "/api/v1/observers", opID: "listObservers", summary: "List the tenant's external observers", handler: a.listObservers, resSchema: "ObserverList", successCode: "200", perm: authz.NotificationsRead},
		{method: "PUT", path: "/api/v1/observers/{id}", opID: "updateObserver", summary: "Replace an external observer's configuration", handler: a.updateObserver, pathParams: idPath, reqSchema: "ObserverRequest", resSchema: "Observer", successCode: "200", mutation: true, perm: authz.NotificationsWrite},
		{method: "POST", path: "/api/v1/observations", opID: "recordObservation", summary: "Report what an observer saw at an endpoint; trstctl compares it with the certificate deployed there", handler: a.recordObservation, reqSchema: "ObservationRequest", resSchema: "Observation", successCode: "201", mutation: true, perm: authz.DiscoveryWrite},
		{method: "GET", path: "/api/v1/observations", opID: "listObservations", summary: "List external observations and their verdicts", handler: a.listObservations, query: observationQuery, resSchema: "ObservationList", successCode: "200", perm: authz.DiscoveryRead},
	}
}
