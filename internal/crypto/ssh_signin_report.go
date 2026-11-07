// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"
)

// A274: bypass detection reads a host's sign-in records through the
// provider's administrator connection, as account discovery reads its
// accounts (A260): one fixed read-only script, its output bounded. It reads
// sign-in metadata only — who signed in, when, from where and how — for the
// named managed accounts, never a credential or what a session did.

// sshSignInReportLimit bounds a host's sign-in report.
const sshSignInReportLimit = 4 << 20

// signInAccount is an account name a report may filter by (pamsignin's
// rule): no quote, space or shell character can occur in it.
var signInAccount = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@\\-]{0,127}$`)

// sshSignInScript is the Linux and Unix script: the host's UTC offset, then
// sshd's "Accepted" lines for the named accounts from the journal (since the
// given time) and from the auth log files, then an end marker. %s is the
// fixed-string filter arguments, %d the time in Unix seconds.
const sshSignInScript = `LC_ALL=C; export LC_ALL
echo "=== tz $(date +%%z)"
signins() { grep -E 'sshd(-session)?\[[0-9]+\]: Accepted ' | grep -F %s | tail -n 5000; }
echo '=== journal'
if command -v journalctl >/dev/null 2>&1; then
  journalctl -q --no-pager -o short-iso-precise --since '@%d' 2>/dev/null | signins
fi
for f in /var/log/auth.log /var/log/secure; do
  [ -r "$f" ] || continue
  echo "=== file $f"
  signins < "$f"
done
echo '=== end'
`

// sshWindowsSignInScript is the Windows script (PowerShell over OpenSSH, as
// the Windows rotation profile, A240): the Security log's logon events (4624)
// of the named accounts since the given time, one line each —
// time|domain|account|logon type|address|logon id — then an end marker.
const sshWindowsSignInScript = "$ErrorActionPreference = 'Stop'\n" +
	"$accounts = @(%s)\n" +
	"$since = [DateTime]::Parse('%s', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal)\n" +
	"Write-Output '=== windows'\n" +
	"Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$since.ToLocalTime()} -ErrorAction SilentlyContinue | ForEach-Object {\n" +
	"  $x = [xml]$_.ToXml(); $d = @{}\n" +
	"  foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = [string]$n.'#text' }\n" +
	"  if ($accounts -contains $d['TargetUserName']) {\n" +
	"    '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.TimeCreated.ToUniversalTime().ToString('o'), $d['TargetDomainName'], $d['TargetUserName'], $d['LogonType'], $d['IpAddress'], $d['TargetLogonId']\n" +
	"  }\n" +
	"}\n" +
	"Write-Output '=== end'\n"

// SSHSignInScript is the script ReadSSHSignInReport runs for the accounts
// since a time: the shell script on a Linux or Unix host, the PowerShell
// command line on a Windows one.
func SSHSignInScript(windows bool, accounts []string, since time.Time) (string, error) {
	if len(accounts) == 0 || len(accounts) > 256 {
		return "", errors.New("a sign-in report names 1-256 accounts")
	}
	for _, a := range accounts {
		if !signInAccount.MatchString(a) {
			return "", errors.New("a sign-in report's account names carry no quote, space or shell character")
		}
	}
	if windows {
		quoted := make([]string, len(accounts))
		for i, a := range accounts {
			quoted[i] = "'" + a + "'"
		}
		script := fmt.Sprintf(sshWindowsSignInScript, strings.Join(quoted, ","), since.UTC().Format(time.RFC3339))
		units := utf16.Encode([]rune(script))
		raw := make([]byte, 0, 2*len(units))
		for _, unit := range units {
			raw = binary.LittleEndian.AppendUint16(raw, unit)
		}
		return "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + base64.StdEncoding.EncodeToString(raw), nil
	}
	filters := make([]string, len(accounts))
	for i, a := range accounts {
		filters[i] = "-e '" + "for " + a + " from " + "'"
	}
	return fmt.Sprintf(sshSignInScript, strings.Join(filters, " "), since.Unix()), nil
}

// ReadSSHSignInReport runs the sign-in script on the host over its pinned
// administrator connection and returns the framed report.
func ReadSSHSignInReport(ctx context.Context, target SSHAccountTarget, adminPKCS8 []byte, accounts []string, since time.Time) ([]byte, error) {
	script, err := SSHSignInScript(target.Windows, accounts, since)
	if err != nil {
		return nil, err
	}
	key, err := LockedKeyFromPKCS8PEM(adminPKCS8)
	if err != nil {
		return nil, errors.New("a sign-in report requires a supported PKCS#8 administrator key")
	}
	defer key.Destroy()
	signer, err := sshSignerFromDigestSigner(key)
	if err != nil {
		return nil, errors.New("a sign-in report's administrator key cannot authenticate")
	}
	client, closeClient, err := dialPinnedSSH(ctx, target, target.AdminUser, ssh.PublicKeys(signer))
	if err != nil {
		return nil, err
	}
	defer closeClient()
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = session.Close() }()
	var out bytes.Buffer
	session.Stdout = &signInLimitedBuffer{buf: &out, limit: sshSignInReportLimit}
	command := script
	if !target.Windows {
		session.Stdin = strings.NewReader(script)
		command = "sh -s"
	}
	if err := session.Run(command); err != nil {
		return nil, errors.New("the sign-in report failed on the host")
	}
	return out.Bytes(), nil
}

type signInLimitedBuffer struct {
	buf   *bytes.Buffer
	limit int
}

func (l *signInLimitedBuffer) Write(p []byte) (int, error) {
	if l.buf.Len()+len(p) > l.limit {
		return 0, errors.New("the sign-in report exceeds its bound")
	}
	return l.buf.Write(p)
}
