// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"sort"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/a10"
	"trstctl.com/trstctl/internal/connector/acm"
	"trstctl.com/trstctl/internal/connector/apache"
	"trstctl.com/trstctl/internal/connector/azurekv"
	"trstctl.com/trstctl/internal/connector/caddy"
	"trstctl.com/trstctl/internal/connector/cisco"
	"trstctl.com/trstctl/internal/connector/elasticsearch"
	"trstctl.com/trstctl/internal/connector/envoy"
	"trstctl.com/trstctl/internal/connector/f5"
	"trstctl.com/trstctl/internal/connector/fortigate"
	"trstctl.com/trstctl/internal/connector/gcpcm"
	"trstctl.com/trstctl/internal/connector/haproxy"
	"trstctl.com/trstctl/internal/connector/iis"
	"trstctl.com/trstctl/internal/connector/javakeystore"
	"trstctl.com/trstctl/internal/connector/kemp"
	"trstctl.com/trstctl/internal/connector/mysql"
	"trstctl.com/trstctl/internal/connector/netscaler"
	"trstctl.com/trstctl/internal/connector/nginx"
	"trstctl.com/trstctl/internal/connector/paloalto"
	"trstctl.com/trstctl/internal/connector/postfix"
	"trstctl.com/trstctl/internal/connector/postgresql"
	"trstctl.com/trstctl/internal/connector/rabbitmq"
	"trstctl.com/trstctl/internal/connector/tomcat"
	"trstctl.com/trstctl/internal/connector/traefik"
	"trstctl.com/trstctl/internal/pluginhost"
)

// NativeConnectorGrant is the sandbox grant census for every family this
// binary ships (A74/A75): the kinds of operation the family's connector asks
// for, read from a prototype built with empty configuration and, where an
// option widens the grant, with that option set, so the census names the most
// a family may ask for. A real attempt narrows these kinds to the target's
// paths and host; it never widens them. The census is independent of what
// connectors.enabled turns on in this process, because a host family is
// executed by the enrolled host agent — the same connector code linked into
// the agent — whether or not the control plane enabled it for itself.
func NativeConnectorGrant(name string) (pluginhost.Grant, bool) {
	var prototype connector.Connector
	switch name {
	case "nginx":
		prototype = nginx.New("", "")
	case "apache":
		prototype = apache.New("", "")
	case "caddy":
		prototype = caddy.New("", "")
	case "iis":
		prototype = iis.New("")
	case "haproxy":
		prototype = haproxy.New("", "")
	case "postfix":
		prototype = postfix.New(postfix.Config{})
	case "traefik":
		prototype = traefik.New("", "")
	case "java-keystore":
		prototype = javakeystore.New("", nil, "", javakeystore.WithReloadAction("reload"))
	case "postgresql":
		prototype = postgresql.New("", "")
	case "mysql":
		prototype = mysql.New("", "")
	case "rabbitmq":
		prototype = rabbitmq.New("", "")
	case "elasticsearch":
		prototype = elasticsearch.New("", "")
	case "tomcat":
		prototype = tomcat.New("", "")
	case "envoy":
		prototype = envoy.New("", "")
	case "f5":
		prototype = f5.New("", "")
	case "netscaler":
		prototype = netscaler.New("", "", nil)
	case "a10":
		prototype = a10.New("", "", nil)
	case "kemp":
		prototype = kemp.New("", nil)
	case "cisco":
		prototype = cisco.New("", "", nil)
	case "fortigate":
		prototype = fortigate.New("", nil)
	case "paloalto":
		prototype = paloalto.New("", nil)
	case "aws-acm":
		prototype = acm.New("", acm.Credentials{})
	case "azure-keyvault":
		prototype = azurekv.New("", nil)
	case "gcp-certificate-manager":
		prototype = gcpcm.New("", "", nil)
	default:
		return pluginhost.Grant{}, false
	}
	return prototype.Capabilities(), true
}

// NativeConnectorGrantNames is the census as the catalog serves it: sorted
// capability names, or nil for a family this binary does not ship.
func NativeConnectorGrantNames(name string) []string {
	grant, ok := NativeConnectorGrant(name)
	if !ok {
		return nil
	}
	caps := grant.Capabilities()
	out := make([]string, 0, len(caps))
	for _, capability := range caps {
		out = append(out, string(capability))
	}
	sort.Strings(out)
	return out
}
