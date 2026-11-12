// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Kubernetes service account token decoys (Q6-O2). The operator registers a
// decoy — a service account bound to nothing and its token Secret — and
// applies the manifest the response carries; trstctl never holds the token.
// The cluster's API server sends its audit events to its cluster's
// audit-events route with a token holding only decoys:events.report. A read of the decoy's Secret
// (get, or a list or watch of its namespace's Secrets) names the principal
// that read it; any request made with the token names the client that sent
// it. Each distinct reader raises one critical alert.

// kubernetesAuditBodyLimit bounds one audit batch: the API server sends up to
// 400 events a batch by default, each a few kilobytes at Metadata level.
const kubernetesAuditBodyLimit = 8 << 20

// maxKubernetesAuditEvents bounds the events one batch is matched over.
const maxKubernetesAuditEvents = 4000

// kubernetesTokenController is the authenticated principal the cluster's
// token controller runs as (the controller manager's own identity): it reads
// a token Secret to fill it, and that read is not a theft. The name is the
// API server's authentication result, which a client cannot choose.
const kubernetesTokenController = "system:kube-controller-manager" // #nosec G101 -- a Kubernetes user name, not a credential (CWE-798)

var (
	kubernetesClusterName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,126}[a-z0-9])?$`)
	kubernetesLabelName   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	kubernetesObjectName  = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
)

type kubernetesDecoyRegisterRequest struct {
	Cluster        string `json:"cluster"`
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"service_account"`
	SecretName     string `json:"secret_name,omitempty"`
	Name           string `json:"name"`
	Placement      string `json:"placement"`
}

// kubernetesDecoyRegistration is the registered decoy, the manifest that plants
// it and the audit rules its cluster's policy needs.
type kubernetesDecoyRegistration struct {
	store.HoneyToken
	Manifest    string `json:"manifest"`
	AuditPolicy string `json:"audit_policy"`
}

func (a *API) kubernetesDecoyRoutes() []route {
	idPath := []param{pathUUID("id")}
	return []route{
		{method: "POST", path: "/api/v1/secrets/honeytokens/kubernetes", opID: "registerKubernetesDecoy",
			summary: "Register a Kubernetes service account token decoy and get the manifest that plants it",
			handler: a.registerKubernetesDecoy, reqSchema: "KubernetesDecoyRegisterRequest", resSchema: "KubernetesDecoyRegistration",
			successCode: "201", mutation: true, perm: authz.SecretsWrite},
		{method: "GET", path: "/api/v1/secrets/honeytokens/kubernetes", opID: "listKubernetesDecoys",
			summary: "List Kubernetes token decoys and who first read or used each one",
			handler: a.listKubernetesDecoys, query: []param{
				{name: "limit", typ: "integer", desc: "page size (1-100)"},
				{name: "cursor", typ: "string", desc: "opaque pagination cursor"},
			}, resSchema: "KubernetesDecoyList", successCode: "200", perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/honeytokens/kubernetes/{id}/retire", opID: "retireKubernetesDecoy",
			summary: "Stop alerting on a Kubernetes token decoy; its service account and Secret stay in the cluster",
			handler: a.retireKubernetesDecoy, pathParams: idPath, resSchema: "KubernetesDecoy", successCode: "200",
			mutation: true, perm: authz.SecretsWrite},
		// The cluster is a path segment, not a query parameter: the API
		// server's webhook client keeps the path of its kubeconfig's server URL
		// and drops its query.
		{method: "POST", path: "/api/v1/secrets/honeytokens/kubernetes/clusters/{cluster}/audit-events", opID: "reportKubernetesAuditEvents",
			summary: "Take a cluster API server's audit webhook batch and alert on reads and uses of its decoys",
			handler: a.reportKubernetesAuditEvents, pathParams: []param{
				{name: "cluster", typ: "string", desc: "the cluster as its decoys were registered"},
			}, reqSchema: "KubernetesAuditEventList", resSchema: "KubernetesAuditReport", successCode: "200",
			perm: authz.DecoyEventsReport},
	}
}

//trstctl:mutation
func (a *API) registerKubernetesDecoy(w http.ResponseWriter, r *http.Request) {
	if a.orch == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "decoys are not configured"))
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req kubernetesDecoyRegisterRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Cluster, req.Namespace = strings.TrimSpace(req.Cluster), strings.TrimSpace(req.Namespace)
		req.ServiceAccount, req.SecretName = strings.TrimSpace(req.ServiceAccount), strings.TrimSpace(req.SecretName)
		req.Name, req.Placement = strings.TrimSpace(req.Name), strings.TrimSpace(req.Placement)
		if req.SecretName == "" {
			req.SecretName = req.ServiceAccount + "-token"
		}
		switch {
		case !kubernetesClusterName.MatchString(req.Cluster):
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "cluster must be a lowercase name of 1-128 letters, digits, dots and dashes")
		case !kubernetesLabelName.MatchString(req.Namespace):
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "namespace must be a Kubernetes namespace name (RFC 1123 label)")
		case !kubernetesObjectName.MatchString(req.ServiceAccount) || !kubernetesObjectName.MatchString(req.SecretName):
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "service_account and secret_name must be Kubernetes object names (RFC 1123 subdomain)")
		case !validHoneyTokenLabel(req.Name, 128) || !validHoneyTokenLabel(req.Placement, 256):
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "name (1-128 characters) and placement (1-256 characters) are required without control characters")
		}
		var h store.HoneyToken
		err := a.store.WithProjectionLock(ctx, func(ctx context.Context) error {
			var err error
			h, err = a.orch.RegisterKubernetesDecoy(ctx, tenantID, req.Name, req.Placement, req.Cluster, req.Namespace, req.ServiceAccount, req.SecretName)
			if errors.Is(err, orchestrator.ErrKubernetesDecoyExists) {
				return errStatus(http.StatusConflict, "this service account is already a live decoy on this cluster")
			}
			return err
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, kubernetesDecoyRegistration{HoneyToken: h,
			Manifest: kubernetesDecoyManifest(h), AuditPolicy: kubernetesDecoyAuditRules(h)}, nil
	})
}

// kubernetesDecoyManifest plants the decoy: a service account that mounts no
// token and is bound to nothing, and its long-lived token Secret, which the
// cluster's token controller fills. Nothing in it says decoy.
func kubernetesDecoyManifest(h store.HoneyToken) string {
	return fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: %[1]s
  namespace: %[2]s
automountServiceAccountToken: false
---
apiVersion: v1
kind: Secret
metadata:
  name: %[3]s
  namespace: %[2]s
  annotations:
    kubernetes.io/service-account.name: %[1]s
type: kubernetes.io/service-account-token
`, h.K8sServiceAccount, h.K8sNamespace, h.K8sSecret)
}

// kubernetesDecoyAuditRules are the audit policy rules the cluster needs, ahead
// of any rule that would drop these requests (the first matching rule wins).
func kubernetesDecoyAuditRules(h store.HoneyToken) string {
	return fmt.Sprintf(`# Add ahead of any rule that drops these requests.
- level: Metadata
  users: ["system:serviceaccount:%[1]s:%[2]s"]
- level: Metadata
  resources:
  - group: ""
    resources: ["secrets"]
  namespaces: ["%[1]s"]
`, h.K8sNamespace, h.K8sServiceAccount)
}

func (a *API) listKubernetesDecoys(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatusFrom(http.StatusBadRequest, err))
		return
	}
	items, err := a.store.ListKubernetesDecoysPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	next := ""
	if len(items) == limit {
		next = encodeCursor(items[len(items)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func (a *API) kubernetesDecoy(ctx context.Context, tenantID, id string) (store.HoneyToken, error) {
	h, err := a.store.GetHoneyToken(ctx, tenantID, id)
	if store.IsNotFound(err) || (err == nil && h.Kind != "kubernetes") {
		return store.HoneyToken{}, errStatus(http.StatusNotFound, "Kubernetes decoy not found")
	}
	return h, err
}

//trstctl:mutation
func (a *API) retireKubernetesDecoy(w http.ResponseWriter, r *http.Request) {
	if a.orch == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "decoys are not configured"))
		return
	}
	id := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		h, err := a.kubernetesDecoy(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		if h.State != "revoked" {
			if err := a.orch.RevokeHoneyToken(ctx, tenantID, id); err != nil {
				return 0, nil, err
			}
		}
		h, err = a.kubernetesDecoy(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, h, nil
	})
}

// kubernetesAuditEventList is the part of an audit.k8s.io/v1 EventList the
// decoys are matched on; every other field is ignored.
type kubernetesAuditEventList struct {
	Items []kubernetesAuditEvent `json:"items"`
}

type kubernetesAuditEvent struct {
	AuditID    string `json:"auditID"`
	Stage      string `json:"stage"`
	RequestURI string `json:"requestURI"`
	Verb       string `json:"verb"`
	User       struct {
		Username string `json:"username"`
	} `json:"user"`
	SourceIPs []string `json:"sourceIPs"`
	UserAgent string   `json:"userAgent"`
	ObjectRef *struct {
		Resource  string `json:"resource"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		APIGroup  string `json:"apiGroup"`
	} `json:"objectRef"`
	ResponseStatus *struct {
		Code int `json:"code"`
	} `json:"responseStatus"`
}

type kubernetesAuditReport struct {
	Events   int `json:"events"`
	Matched  int `json:"matched"`
	Recorded int `json:"recorded"`
}

// kubernetesDecoyHit is one audit event that read or used a decoy.
type kubernetesDecoyHit struct {
	decoyID, reader, method, requestURI string
}

// matchKubernetesDecoyEvents finds the events that read a decoy's Secret or
// used its token. Only a finished request counts (stage ResponseComplete, or
// Panic), so each request is seen once whatever stages the policy logs. A read
// is a get of the Secret, or a list or watch of its namespace's Secrets, by
// anyone but the decoy itself and the token controller filling it, refused or
// not, unless nothing was found (404); the reader is the principal and its
// address.
// A use is any request authenticated as the decoy's service account; the
// reader is the client — its user agent and address — since the principal is
// the decoy.
func matchKubernetesDecoyEvents(decoys []store.HoneyToken, events []kubernetesAuditEvent) []kubernetesDecoyHit {
	var hits []kubernetesDecoyHit
	for _, e := range events {
		if e.Stage != "ResponseComplete" && e.Stage != "Panic" {
			continue
		}
		code := ""
		if e.ResponseStatus != nil && e.ResponseStatus.Code > 0 {
			code = " (" + strconv.Itoa(e.ResponseStatus.Code) + ")"
		}
		from := ""
		if len(e.SourceIPs) > 0 {
			from = " from " + boundedAuditText(e.SourceIPs[0], 64)
		}
		for _, d := range decoys {
			account := "system:serviceaccount:" + d.K8sNamespace + ":" + d.K8sServiceAccount
			if e.User.Username == account {
				client := boundedAuditText(e.UserAgent, 256)
				if client == "" {
					client = "an unnamed client"
				}
				resource := ""
				if e.ObjectRef != nil {
					resource = " " + boundedAuditText(e.ObjectRef.Resource, 64)
				}
				hits = append(hits, kubernetesDecoyHit{decoyID: d.ID, reader: client + from,
					method: "token used: " + boundedAuditText(e.Verb, 32) + resource + code, requestURI: boundedAuditText(e.RequestURI, 1024)})
				continue
			}
			ref := e.ObjectRef
			if ref == nil || ref.Resource != "secrets" || ref.APIGroup != "" || ref.Namespace != d.K8sNamespace {
				continue
			}
			if e.ResponseStatus != nil && e.ResponseStatus.Code == http.StatusNotFound {
				continue // no Secret was there to read: kubectl apply looks before it creates
			}
			if e.User.Username == kubernetesTokenController {
				continue // the token controller reads the Secret it fills
			}
			switch {
			case ref.Name == d.K8sSecret && (e.Verb == "get" || e.Verb == "list" || e.Verb == "watch"):
			case ref.Name == "" && (e.Verb == "list" || e.Verb == "watch"):
			default:
				continue
			}
			reader := boundedAuditText(e.User.Username, 256)
			if reader == "" {
				reader = "an unnamed principal"
			}
			hits = append(hits, kubernetesDecoyHit{decoyID: d.ID, reader: reader + from,
				method: "token Secret read: " + boundedAuditText(e.Verb, 32) + " secrets" + code, requestURI: boundedAuditText(e.RequestURI, 1024)})
		}
	}
	return hits
}

// boundedAuditText keeps at most n bytes of printable text from an audit
// event field, which the cluster's clients choose.
func boundedAuditText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, strings.ToValidUTF8(strings.TrimSpace(s), "?"))
	for len(s) > n {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

func (a *API) reportKubernetesAuditEvents(w http.ResponseWriter, r *http.Request) {
	if a.orch == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "decoys are not configured"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	cluster := r.PathValue("cluster")
	if !kubernetesClusterName.MatchString(cluster) {
		a.writeError(w, errStatus(http.StatusBadRequest, "cluster must name the cluster as its decoys were registered"))
		return
	}
	var batch kubernetesAuditEventList
	if err := decodeJSONWithLimit(r, &batch, kubernetesAuditBodyLimit); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if len(batch.Items) > maxKubernetesAuditEvents {
		a.writeError(w, errStatus(http.StatusRequestEntityTooLarge, fmt.Sprintf("an audit batch carries at most %d events", maxKubernetesAuditEvents)))
		return
	}
	decoys, err := a.store.LiveKubernetesDecoys(r.Context(), tenantID, cluster)
	if err != nil {
		a.writeError(w, err)
		return
	}
	report := kubernetesAuditReport{Events: len(batch.Items)}
	for _, hit := range matchKubernetesDecoyEvents(decoys, batch.Items) {
		report.Matched++
		if err := a.orch.RecordKubernetesDecoyEvent(r.Context(), tenantID, hit.decoyID, hit.reader, hit.method, hit.requestURI); err != nil {
			// The API server sends the batch again on an error; an alert
			// already queued for a reader is not queued twice.
			a.writeError(w, err)
			return
		}
		report.Recorded++
	}
	a.writeJSON(w, http.StatusOK, report)
}
