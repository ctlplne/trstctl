// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// userPassword is a two-user rotation's credential: an account and its
// password, as the Oracle and SQL Server providers publish it.
type userPassword struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// twoUserApp is the application in the A240 two-user proofs: every tick it
// reads the secret, connects with whatever credential it last read (through
// connects), and reports a version verified once it connected with it.
type twoUserApp struct {
	secret   string
	connects func(username, password string) bool
	base     string
	token    string
	client   *http.Client
	paused   atomic.Bool
	quiet    atomic.Bool

	mu         sync.Mutex
	version    int
	credential userPassword
	reported   int
	logins     map[string]int
	failures   []string
}

func (app *twoUserApp) run(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		app.tick(ctx)
	}
}

func (app *twoUserApp) tick(ctx context.Context) {
	var read struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	readOK := false
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, app.base+"/api/v1/secrets/store/"+app.secret, nil); err == nil {
		req.Header.Set("Authorization", "Bearer "+app.token)
		if resp, err := app.client.Do(req); err == nil {
			readOK = resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&read) == nil
			_ = resp.Body.Close()
		}
	}
	app.mu.Lock()
	current, credential := app.version, app.credential
	app.mu.Unlock()
	if readOK && read.Version != current {
		var next userPassword
		if json.Unmarshal([]byte(read.Value), &next) != nil || !app.connects(next.Username, next.Password) {
			app.fail(fmt.Sprintf("adopt version %d", read.Version))
		} else {
			app.mu.Lock()
			app.version, app.credential = read.Version, next
			app.mu.Unlock()
			current, credential = read.Version, next
		}
	}
	if current == 0 {
		return
	}
	if !app.connects(credential.Username, credential.Password) {
		if ctx.Err() == nil {
			app.fail(fmt.Sprintf("connect with version %d", current))
		}
		return
	}
	app.mu.Lock()
	app.logins[credential.Username]++
	reported := app.reported
	app.mu.Unlock()
	if current != reported && !app.quiet.Load() && app.report(ctx, current) == nil {
		app.mu.Lock()
		app.reported = current
		app.mu.Unlock()
	}
}

func (app *twoUserApp) fail(message string) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.paused.Load() {
		message = "paused: " + message
	}
	app.failures = append(app.failures, message)
}

func (app *twoUserApp) report(ctx context.Context, version int) error {
	body, _ := json.Marshal(map[string]any{"consumer": "orders-app", "state": "verified",
		"secrets": []map[string]any{{"name": app.secret, "version": version}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, app.base+"/api/v1/secrets/deliveries", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+app.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", fmt.Sprintf("%s-verified-%d", app.secret, version))
	resp, err := app.client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("report version %d: HTTP %d", version, resp.StatusCode)
	}
	return nil
}

func (app *twoUserApp) snapshot() (map[string]int, []string) {
	app.mu.Lock()
	defer app.mu.Unlock()
	logins := map[string]int{}
	for user, n := range app.logins {
		logins[user] = n
	}
	return logins, append([]string(nil), app.failures...)
}
