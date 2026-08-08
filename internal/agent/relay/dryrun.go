// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Dry-run: find out whether a deploy would work, without doing one (epic D5).
//
// The console's "test connection" button used to record a receipt saying the
// target's configuration parsed. That is true and nearly useless: it does not
// tell an operator whether the appliance is reachable, whether the credential
// still works, or whether the endpoint is the one they think it is. The status
// was renamed to say so honestly (config_validated) rather than claiming a test
// had passed. This is the test.
//
// Zero writes is a structural property here, not a promise. A dry-run NEVER
// calls connector.Run — it does not construct the connector's deploy path at
// all. What it does is resolve everything a deploy would need and probe the
// endpoint with a read-only request, then describe what a real deploy would
// change. A connector's Deploy method is the only code that mutates a target,
// and it is not on this path.

// PlanStepStatus is the outcome of one dry-run step.
type PlanStepStatus string

const (
	// StepOK means the step resolved and a real deploy would proceed past it.
	StepOK PlanStepStatus = "ok"
	// StepFailed means a real deploy would stop here. The step's Detail says
	// why, in the specific terms an operator can act on — "connection refused",
	// not "test failed".
	StepFailed PlanStepStatus = "failed"
	// StepSkipped means the step does not apply to this connector.
	StepSkipped PlanStepStatus = "skipped"
)

// PlanStep is one thing a deploy would have to do, and whether it could.
type PlanStep struct {
	Name   string         `json:"name"`
	Status PlanStepStatus `json:"status"`
	Detail string         `json:"detail,omitempty"`
}

// Plan is what a real deploy would change, and whether it could run at all.
type Plan struct {
	Connector string     `json:"connector"`
	Target    string     `json:"target"`
	Endpoint  string     `json:"endpoint,omitempty"`
	Steps     []PlanStep `json:"steps"`
	// WouldMutate names, in operator language, what a real deploy would change
	// on the target. It is populated only when every step passed: describing a
	// mutation that could not happen would read as a plan rather than as a
	// failure.
	WouldMutate []string `json:"would_mutate,omitempty"`
	// Ready is true when a real deploy would proceed. It is the single answer
	// the console shows; the steps are why.
	Ready bool `json:"ready"`
}

// dryRunProbeTimeout bounds the reachability check. A dry-run is an interactive
// operation behind a console button — an operator waiting thirty seconds for a
// "cannot reach" answer will conclude the product is broken rather than the
// target.
const dryRunProbeTimeout = 10 * time.Second

// DryRun resolves everything a deploy would need and probes the target, without
// changing anything.
//
// It takes the same intent and redeemed material a real deploy takes, so a
// dry-run that passes is evidence about the deploy that would follow — not
// about a differently-configured dry-run path.
func DryRun(ctx context.Context, client *http.Client, intent DeployIntent, material Material) (Plan, error) {
	plan := Plan{Connector: intent.Connector, Target: intent.Target}

	if !Executes(intent.Connector) {
		plan.Steps = append(plan.Steps, PlanStep{
			Name: "connector", Status: StepFailed,
			Detail: fmt.Sprintf("connector %q is not executable by this relay", intent.Connector),
		})
		return plan, nil
	}
	plan.Steps = append(plan.Steps, PlanStep{
		Name: "connector", Status: StepOK,
		Detail: "this relay carries an executor for " + intent.Connector,
	})

	var target TargetConfig
	if len(intent.TargetConfig) > 0 {
		if err := json.Unmarshal(intent.TargetConfig, &target); err != nil {
			plan.Steps = append(plan.Steps, PlanStep{
				Name: "target-config", Status: StepFailed,
				Detail: "target configuration did not decode: " + err.Error(),
			})
			return plan, nil
		}
	}
	endpoint := strings.TrimSpace(target.Endpoint)
	if endpoint == "" {
		plan.Steps = append(plan.Steps, PlanStep{
			Name: "target-config", Status: StepFailed,
			Detail: "target configuration carries no endpoint",
		})
		return plan, nil
	}
	plan.Endpoint = endpoint
	plan.Steps = append(plan.Steps, PlanStep{
		Name: "target-config", Status: StepOK,
		Detail: "target configuration resolved for " + endpoint,
	})

	// Credential resolution, using the SAME require semantics the executor uses,
	// so a dry-run cannot pass on a credential set a deploy would reject.
	if _, err := buildRelayConnector(intent.Connector, target, material); err != nil {
		plan.Steps = append(plan.Steps, PlanStep{
			Name: "credentials", Status: StepFailed,
			// The error names which reference is missing, never a value.
			Detail: err.Error(),
		})
		return plan, nil
	}
	plan.Steps = append(plan.Steps, PlanStep{
		Name: "credentials", Status: StepOK,
		Detail: "every credential this connector needs was redeemed for this attempt",
	})

	// Reachability. A read-only request: the endpoint either answers or it does
	// not, and either answer is information. A non-2xx response is NOT a failure
	// — appliance management APIs routinely return 401 or 404 on a bare GET to
	// their base URL, and treating that as unreachable would tell operators
	// their working F5 is down.
	step := probeEndpoint(ctx, client, endpoint)
	plan.Steps = append(plan.Steps, step)
	if step.Status == StepFailed {
		return plan, nil
	}

	plan.Ready = true
	plan.WouldMutate = wouldMutate(intent.Connector, target)
	return plan, nil
}

// probeEndpoint performs the one network call a dry-run makes. GET, no body, no
// state: the request cannot change anything on the target even if the target
// wanted it to.
func probeEndpoint(ctx context.Context, client *http.Client, endpoint string) PlanStep {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return PlanStep{
			Name: "reachability", Status: StepFailed,
			Detail: fmt.Sprintf("endpoint %q is not a usable URL", endpoint),
		}
	}
	probeCtx, cancel := context.WithTimeout(ctx, dryRunProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return PlanStep{Name: "reachability", Status: StepFailed, Detail: "could not build a probe request"}
	}
	if client == nil {
		// No silent fallback to the ambient client: the caller configures the
		// relay's transport deliberately (timeouts, redirect policy, trust), and
		// quietly substituting a different one would make the probe test
		// something other than what a deploy would use.
		return PlanStep{
			Name: "reachability", Status: StepFailed,
			Detail: "no HTTP client was configured for this relay",
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		// The transport error is the useful part — "connection refused",
		// "certificate signed by unknown authority", "no such host" each send an
		// operator somewhere different. It names the endpoint, which the
		// operator supplied, and carries no credential: the probe sends none.
		return PlanStep{
			Name: "reachability", Status: StepFailed,
			Detail: "could not reach the target: " + summarizeTransportError(err),
		}
	}
	defer func() { _ = resp.Body.Close() }()
	return PlanStep{
		Name: "reachability", Status: StepOK,
		Detail: fmt.Sprintf("target answered on %s (HTTP %d); a non-2xx here is normal for a management API probed without a request path",
			parsed.Host, resp.StatusCode),
	}
}

// summarizeTransportError keeps the diagnostic and drops the rest. A Go
// transport error embeds the full URL including any query string; the endpoint
// is operator-supplied and carries no secret, but the habit of trimming what is
// forwarded is the right one on a path that runs beside credential handling.
func summarizeTransportError(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err.Error()
	}
	return err.Error()
}

// wouldMutate describes, in operator language, what a real deploy would change.
//
// It is per connector family rather than generic, because "it would deploy a
// certificate" tells an operator nothing they did not already know. What they
// want to know before authorizing is which named object on their appliance is
// about to be replaced.
func wouldMutate(connectorName string, target TargetConfig) []string {
	object := strings.TrimSpace(target.ObjectName)
	if object == "" {
		object = "an object named after the deployment target"
	}
	switch connectorName {
	case "f5":
		profile := strings.TrimSpace(target.ClientSSLProfile)
		if profile == "" {
			profile = "the configured client-SSL profile"
		}
		steps := []string{
			"upload the certificate and key to /mgmt/shared/file-transfer as " + object,
			"create or replace the sys crypto cert and key objects for " + object,
			"point client-SSL profile " + profile + " at the new certificate",
		}
		if peer := strings.TrimSpace(target.PeerEndpoint); peer != "" {
			// HA pair (E1): the same three changes happen on the standby too,
			// because its certificate store does not replicate from the active
			// node. Naming the peer here is what tells an operator this is a
			// two-appliance change before they authorize it.
			steps = append(steps, "repeat all of the above on the HA peer "+peer+" (its certificate store does not sync)")
		}
		return steps
	case "netscaler":
		location := strings.TrimSpace(target.FileLocation)
		if location == "" {
			location = "the appliance's default certificate directory"
		}
		return []string{
			"upload the certificate and key into " + location,
			"update the sslcertkey binding for " + object,
		}
	case "a10", "cisco":
		return []string{
			"upload the certificate and key to the device's certificate store",
			"rebind " + object + " to the new certificate",
		}
	case "kemp":
		return []string{"replace the certificate on virtual service " + object}
	case "fortigate":
		return []string{"import the certificate as " + object + " and rebind the SSL profile"}
	case "paloalto":
		return []string{"import the certificate as " + object + " and commit the candidate configuration"}
	default:
		return []string{"replace the certificate bound to " + object}
	}
}
