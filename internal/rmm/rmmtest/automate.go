// SPDX-License-Identifier: BUSL-1.1

package rmmtest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// AutomateComputer is one computer.
type AutomateComputer struct {
	ID       int64
	ClientID int64
	Name     string
	Online   bool
}

// AutomateCommand is one shell line executed on a computer.
type AutomateCommand struct {
	ComputerID int64
	CommandID  int64
	Line       string
}

// Automate is a ConnectWise Automate /cwa/api/v1 stand-in written from the
// calls the published AutomateAPI module makes: POST /cwa/api/v1/apitoken
// {UserName, Password} with the clientID header (AccessToken,
// IsTwoFactorRequired), and, with the bearer and clientID on every call, the
// computers matching a condition ("Client.Id = N" or "Id = N") paged by page
// and pageSize, and CommandExecute of the execute command on one computer;
// errors carry a message.
type Automate struct {
	srv *httptest.Server

	mu        sync.Mutex
	user      string
	password  string
	clientID  string
	commandID int64
	twoFactor bool
	issued    map[string]bool
	computers []AutomateComputer
	commands  []AutomateCommand
	requests  int
	writes    int
	refused   int
	failWrite int
	nextToken int
}

// NewAutomate starts a stand-in for one integrator user, integration client
// ID and execute command.
func NewAutomate(user, password, clientID string, commandID int64) *Automate {
	s := &Automate{user: user, password: password, clientID: clientID, commandID: commandID, issued: map[string]bool{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Close stops the stand-in.
func (s *Automate) Close() { s.srv.Close() }

// URL is the server.
func (s *Automate) URL() string { return s.srv.URL }

// AddComputer records a computer.
func (s *Automate) AddComputer(c AutomateComputer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.computers = append(s.computers, c)
}

// MoveComputer moves a computer to another client.
func (s *Automate) MoveComputer(id, client int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.computers {
		if s.computers[i].ID == id {
			s.computers[i].ClientID = client
		}
	}
}

// RequireTwoFactor makes sign-ins answer that two-factor sign-in is needed.
func (s *Automate) RequireTwoFactor() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.twoFactor = true
}

// FailWritesAfterApplying makes the next n writes take effect and then
// answer 500, as a write whose answer was lost.
func (s *Automate) FailWritesAfterApplying(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWrite = n
}

// Commands returns every executed shell line.
func (s *Automate) Commands() []AutomateCommand {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AutomateCommand(nil), s.commands...)
}

// Counts reports authenticated API requests, applied writes and refused
// requests.
func (s *Automate) Counts() (requests, writes, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, s.writes, s.refused
}

func automateJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func automateComputerJSON(c AutomateComputer) map[string]any {
	status := "Offline"
	if c.Online {
		status = "Online"
	}
	return map[string]any{"Id": c.ID, "ComputerName": c.Name, "Status": status, "Type": "Workstation",
		"Client":   map[string]any{"Id": c.ClientID, "Name": "client " + strconv.FormatInt(c.ClientID, 10)},
		"Location": map[string]any{"Id": c.ClientID * 10, "Name": "main"}}
}

func (s *Automate) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Header.Get("clientID") != s.clientID {
		s.refused++
		automateJSON(w, http.StatusForbidden, map[string]any{"message": "A registered clientID is required"})
		return
	}
	if strings.EqualFold(r.URL.Path, "/cwa/api/v1/apitoken") && r.Method == http.MethodPost {
		var body struct {
			UserName string `json:"UserName"`
			Password string `json:"Password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.UserName != s.user || body.Password != s.password {
			s.refused++
			automateJSON(w, http.StatusUnauthorized, map[string]any{"message": "Username or password is incorrect"})
			return
		}
		if s.twoFactor {
			automateJSON(w, http.StatusOK, map[string]any{"AccessToken": "", "IsTwoFactorRequired": true})
			return
		}
		s.nextToken++
		token := "automate-access-" + strconv.Itoa(s.nextToken)
		s.issued[token] = true
		automateJSON(w, http.StatusOK, map[string]any{"AccessToken": token, "TokenType": "Bearer", "ExpirationDate": "2099-01-01T00:00:00Z",
			"IsTwoFactorRequired": false})
		return
	}
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !s.issued[bearer] {
		s.refused++
		automateJSON(w, http.StatusUnauthorized, map[string]any{"message": "Unauthorized"})
		return
	}
	s.requests++
	path := strings.ToLower(strings.Trim(r.URL.Path, "/"))
	parts := strings.Split(path, "/")
	switch {
	case r.Method == http.MethodGet && path == "cwa/api/v1/computers":
		field, value, found := strings.Cut(r.URL.Query().Get("condition"), " = ")
		want, err := strconv.ParseInt(value, 10, 64)
		if !found || err != nil || (field != "Client.Id" && field != "Id") {
			automateJSON(w, http.StatusBadRequest, map[string]any{"message": "Unsupported condition"})
			return
		}
		size, _ := strconv.Atoi(r.URL.Query().Get("pageSize"))
		if size <= 0 || size > 1000 {
			size = 50
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		var list []AutomateComputer
		for _, c := range s.computers {
			if (field == "Client.Id" && c.ClientID == want) || (field == "Id" && c.ID == want) {
				list = append(list, c)
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		start := (page - 1) * size
		if start > len(list) {
			start = len(list)
		}
		end := start + size
		if end > len(list) {
			end = len(list)
		}
		out := []any{}
		for _, c := range list[start:end] {
			out = append(out, automateComputerJSON(c))
		}
		automateJSON(w, http.StatusOK, out)
	case r.Method == http.MethodPost && len(parts) == 6 && parts[3] == "computers" && parts[5] == "commandexecute":
		id, _ := strconv.ParseInt(parts[4], 10, 64)
		var body struct {
			ComputerID int64 `json:"ComputerId"`
			Command    struct {
				ID int64 `json:"Id"`
			} `json:"Command"`
			Parameters []string `json:"Parameters"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ComputerID != id || body.Command.ID != s.commandID ||
			len(body.Parameters) != 1 || !strings.Contains(body.Parameters[0], "!!! ") {
			automateJSON(w, http.StatusBadRequest, map[string]any{"message": "A command execution names its computer, the execute command and one shell line"})
			return
		}
		known := false
		for _, c := range s.computers {
			known = known || c.ID == id
		}
		if !known {
			automateJSON(w, http.StatusNotFound, map[string]any{"message": "Computer not found"})
			return
		}
		s.commands = append(s.commands, AutomateCommand{ComputerID: id, CommandID: body.Command.ID, Line: body.Parameters[0]})
		s.writes++
		if s.failWrite > 0 {
			s.failWrite--
			automateJSON(w, http.StatusInternalServerError, map[string]any{"message": "An error has occurred"})
			return
		}
		automateJSON(w, http.StatusOK, map[string]any{"Id": 7000 + len(s.commands), "ComputerId": id, "Status": "Pending"})
	default:
		automateJSON(w, http.StatusNotFound, map[string]any{"message": "No HTTP resource was found that matches the request URI"})
	}
}
