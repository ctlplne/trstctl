// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// A270: a network device's own command line over SSH. The administrator signs
// in with its password (password or keyboard-interactive) with the device's
// host key pinned, as for local accounts, and the device's CLI changes account
// passwords. A line carrying a password is written from the caller's bytes and
// the buffer is wiped; transcripts are returned to callers that read only
// configuration facts from them.

// CLIStep is one line typed into the device's CLI and the prompt that ends
// its output (a suffix of the last output line, e.g. "#" or "New password:").
type CLIStep struct {
	Line   []byte
	Prompt string
}

const (
	maxCLIOutput  = 1 << 20
	cliStepWindow = 10 * time.Second
)

// ErrCLIPrompt is a device that did not answer a step with its prompt.
var ErrCLIPrompt = errors.New("network device CLI: the device did not return the expected prompt")

func passwordAuth(password []byte) []ssh.AuthMethod {
	// x/crypto/ssh takes the password as a string; it is built per attempt
	// from the caller's bytes and not kept.
	answer := func() (string, error) { return string(password), nil }
	interactive := func(_, _ string, questions []string, _ []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = string(password)
		}
		return answers, nil
	}
	return []ssh.AuthMethod{ssh.PasswordCallback(answer), ssh.KeyboardInteractive(interactive)}
}

// RunNetworkDeviceCLI signs in to the device as user, opens one interactive
// shell, waits for initialPrompt, and runs steps in order. It returns the
// transcript after the initial prompt; the caller wipes it.
func RunNetworkDeviceCLI(ctx context.Context, target SSHAccountTarget, user string, password []byte, initialPrompt string, steps []CLIStep) ([]byte, error) {
	if !ValidSSHAccountName(user) || len(password) == 0 || initialPrompt == "" {
		return nil, errors.New("network device CLI requires an account, its password and the device's prompt")
	}
	client, closeClient, err := dialPinnedSSH(ctx, target, user, passwordAuth(password)...)
	if err != nil {
		return nil, err
	}
	defer closeClient()
	session, err := client.NewSession()
	if err != nil {
		return nil, errors.New("network device CLI: the device refused a session")
	}
	defer func() { _ = session.Close() }()
	if err := session.RequestPty("vt100", 50, 200, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		return nil, errors.New("network device CLI: the device refused a terminal")
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := session.Shell(); err != nil {
		return nil, errors.New("network device CLI: the device refused a shell")
	}
	chunks := make(chan []byte, 16)
	go func() {
		defer close(chunks)
		for {
			buf := make([]byte, 4096)
			n, err := stdout.Read(buf)
			if n > 0 {
				chunks <- buf[:n]
			}
			if err != nil {
				return
			}
		}
	}()
	var transcript bytes.Buffer
	if err := awaitPrompt(ctx, chunks, &transcript, initialPrompt); err != nil {
		secret.Wipe(transcript.Bytes())
		return nil, err
	}
	transcript.Reset()
	for _, step := range steps {
		line := make([]byte, 0, len(step.Line)+1)
		line = append(append(line, step.Line...), '\n')
		_, err := stdin.Write(line)
		secret.Wipe(line)
		if err != nil {
			secret.Wipe(transcript.Bytes())
			return nil, errors.New("network device CLI: the session closed")
		}
		if err := awaitPrompt(ctx, chunks, &transcript, step.Prompt); err != nil {
			secret.Wipe(transcript.Bytes())
			return nil, err
		}
	}
	return transcript.Bytes(), nil
}

// awaitPrompt reads output into transcript until its last line, trimmed,
// ends with prompt.
func awaitPrompt(ctx context.Context, chunks <-chan []byte, transcript *bytes.Buffer, prompt string) error {
	start := transcript.Len()
	window := time.NewTimer(cliStepWindow)
	defer window.Stop()
	for {
		tail := transcript.Bytes()[start:]
		if i := bytes.LastIndexAny(tail, "\r\n"); i >= 0 {
			tail = tail[i+1:]
		}
		if strings.HasSuffix(strings.TrimRight(string(tail), " \t"), prompt) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-window.C:
			return ErrCLIPrompt
		case chunk, ok := <-chunks:
			if !ok {
				return ErrCLIPrompt
			}
			if transcript.Len()+len(chunk) > maxCLIOutput {
				secret.Wipe(chunk)
				return errors.New("network device CLI: output beyond its bound")
			}
			transcript.Write(chunk)
			secret.Wipe(chunk)
		}
	}
}
