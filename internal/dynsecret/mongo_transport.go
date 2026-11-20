// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"trstctl.com/trstctl/internal/crypto/dbdsn"
	"trstctl.com/trstctl/internal/crypto/dbtls"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secrettext"
)

var errMongoTopology = errors.New("dynsecret mongodb: discovery did not produce a bounded, admitted database topology")

// OpenMongoAdminWithTransport opens a bounded native client for one operation.
func OpenMongoAdminWithTransport(ctx context.Context, dsn []byte, policy *DatabaseTransport) (*MongoDriverAdmin, error) {
	client, err := openMongoProfile(ctx, dsn, policy, dbdsn.Admin)
	if err != nil {
		return nil, err
	}
	return &MongoDriverAdmin{client: client}, nil
}

func openMongoProfile(ctx context.Context, dsn []byte, transport *DatabaseTransport, purpose dbdsn.Purpose) (*mongo.Client, error) {
	target, err := dbdsn.Parse(dbdsn.Mongo, dsn, purpose)
	if err != nil {
		return nil, err
	}
	defer target.Wipe()
	policy := databaseTransport(transport)
	if target.CAFile != "" && len(policy.CAPEM) == 0 {
		return nil, dbdsn.ErrTrust
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	seeds := slices.Clone(target.Hosts)
	if target.SRV {
		seeds, err = resolveMongoSeeds(ctx, &target, policy.Dialer)
		if err != nil {
			return nil, err
		}
	}
	loadBalanced := target.Options["loadbalanced"] == "true"
	direct := target.Options["directconnection"] == "true"
	if loadBalanced && (direct || target.Options["replicaset"] != "") || direct && target.SRV || (loadBalanced || direct) && len(seeds) != 1 {
		return nil, errMongoTopology
	}
	if direct || loadBalanced {
		return openSingleMongo(ctx, target, policy, seeds[0], target.Options["replicaset"], loadBalanced, target.SRV)
	}
	return openMongoPrimary(ctx, target, policy, seeds)
}

func openMongoPrimary(ctx context.Context, target dbdsn.Target, policy DatabaseTransport, seeds []string) (*mongo.Client, error) {
	candidates := slices.Clone(seeds)
	setName := target.Options["replicaset"]
	var lastErr error
	for index := 0; index < len(candidates); index++ {
		endpoint := candidates[index]
		discovered := target.SRV || !slices.Contains(seeds, endpoint)
		client, err := openSingleMongo(ctx, target, policy, endpoint, setName, false, discovered)
		if err != nil {
			lastErr = err
			continue
		}
		hello, err := readMongoTopologyProbe(func(command string) *mongo.SingleResult {
			return client.Database("admin").RunCommand(ctx, bson.D{{Key: command, Value: 1}})
		})
		if err == nil {
			primary, _ := hello.Lookup("isWritablePrimary").BooleanOK()
			if !primary {
				primary, _ = hello.Lookup("ismaster").BooleanOK()
			}
			actualSet, _ := hello.Lookup("setName").StringValueOK()
			if len(actualSet) > 256 || setName != "" && actualSet != setName {
				err = errMongoTopology
			} else if actualSet != "" {
				setName = actualSet
				var peers []string
				peers, err = appendMongoMembers(candidates, hello)
				if err == nil {
					candidates = peers
				}
			}
			if err == nil && primary {
				return client, nil
			}
		}
		closeMongoClient(client)
		if err != nil {
			lastErr = errMongoTopology
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errMongoTopology
}

func readMongoTopologyProbe(run func(string) *mongo.SingleResult) (bson.Raw, error) {
	var hello bson.Raw
	err := run("hello").Decode(&hello)
	var serverErr mongo.ServerError
	if errors.As(err, &serverErr) && serverErr.HasErrorCode(59) {
		// Early supported MongoDB 4.2 releases only register isMaster.
		err = run("isMaster").Decode(&hello)
	}
	return hello, err
}

func appendMongoMembers(current []string, hello bson.Raw) ([]string, error) {
	// Only data-bearing members can be writable candidates. Bound the encoded
	// array before Values allocates a slice from its elements.
	for _, key := range []string{"hosts", "passives"} {
		field := hello.Lookup(key)
		if field.Type == 0 {
			continue
		}
		array, ok := field.ArrayOK()
		if !ok || len(array) > 8*1024 {
			return nil, errMongoTopology
		}
		values, err := array.Values()
		if err != nil || len(values) > dbdsn.MaxHosts {
			return nil, errMongoTopology
		}
		for _, value := range values {
			item, ok := value.StringValueOK()
			host, port, splitErr := net.SplitHostPort(item)
			endpoint, addressErr := dbdsn.TCPAddress(host, port)
			if !ok || splitErr != nil || addressErr != nil {
				return nil, errMongoTopology
			}
			if slices.Contains(current, endpoint) {
				continue
			}
			if len(current) >= dbdsn.MaxHosts {
				return nil, errMongoTopology
			}
			current = append(current, endpoint)
		}
	}
	return current, nil
}

func openSingleMongo(ctx context.Context, target dbdsn.Target, policy DatabaseTransport, endpoint, setName string, loadBalanced, discovered bool) (*mongo.Client, error) {
	dialer := policy.Dialer
	if discovered {
		dialer = dialer.ForDiscoveredPeer()
	}
	credential := options.Credential{Username: target.User, Password: secrettext.String(target.Password),
		PasswordSet: true, AuthSource: target.AuthSource, AuthMechanism: target.Options["authmechanism"]}
	configured := options.Client().SetHosts([]string{endpoint}).SetDialer(dialer).SetAuth(credential).
		SetConnectTimeout(5 * time.Second).SetServerSelectionTimeout(5 * time.Second).SetMaxPoolSize(4).
		SetHTTPClient(policy.Dialer.ForDiscoveredPeer().CertificateStatusClient())
	if loadBalanced {
		configured.SetLoadBalanced(true)
	} else {
		configured.SetDirect(true)
		if setName != "" {
			configured.SetReplicaSet(setName)
		}
	}
	if (target.SRV && target.Options["tls"] != "false") || target.Options["tls"] == "true" {
		name := policy.ServerName
		if name == "" {
			name, _, _ = net.SplitHostPort(endpoint)
		}
		tlsConfig, err := dbtls.Mongo(name, policy.CAPEM)
		if err != nil {
			return nil, dbdsn.ErrTrust
		}
		configured.SetTLSConfig(tlsConfig)
	} else if len(policy.CAPEM) != 0 || policy.ServerName != "" {
		return nil, dbdsn.ErrTrust
	}
	applyMongoOptions(configured, target.Options)
	client, err := mongo.Connect(configured)
	if err != nil {
		return nil, errors.New("dynsecret mongodb: connect failed")
	}
	if err := client.Ping(ctx, nil); err != nil {
		closeMongoClient(client)
		return nil, fmt.Errorf("dynsecret mongodb: ping failed: %w", classifyMongoSignIn(err))
	}
	return client, nil
}

func applyMongoOptions(configured *options.ClientOptions, settings map[string]string) {
	for key, value := range settings {
		millis, _ := strconv.ParseUint(value, 10, 32)
		duration := time.Duration(millis) * time.Millisecond
		switch key {
		case "appname":
			configured.SetAppName(value)
		case "connecttimeoutms":
			if duration > 0 {
				configured.SetConnectTimeout(duration)
			}
		case "serverselectiontimeoutms":
			if duration > 0 {
				configured.SetServerSelectionTimeout(duration)
			}
		case "timeoutms":
			configured.SetTimeout(duration)
		case "maxidletimems":
			configured.SetMaxConnIdleTime(duration)
		case "maxpoolsize":
			if millis > 0 {
				configured.SetMaxPoolSize(millis)
			}
		case "minpoolsize":
			configured.SetMinPoolSize(millis)
		case "retryreads":
			configured.SetRetryReads(value == "true")
		case "retrywrites":
			configured.SetRetryWrites(value == "true")
		}
	}
}

func closeMongoClient(client *mongo.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = client.Disconnect(ctx)
}

func resolveMongoSeeds(ctx context.Context, target *dbdsn.Target, dialer netsec.DatabaseDialer) ([]string, error) {
	host, _, _ := net.SplitHostPort(target.Hosts[0])
	if err := dialer.CheckHost(host); err != nil {
		return nil, errMongoTopology
	}
	_, records, err := net.DefaultResolver.LookupSRV(ctx, "mongodb", "tcp", host)
	if err != nil || len(records) == 0 || len(records) > dbdsn.MaxHosts {
		return nil, errMongoTopology
	}
	labels := strings.Split(host, ".")
	suffix := host
	if len(labels) > 2 {
		suffix = strings.Join(labels[1:], ".")
	}
	seeds := make([]string, 0, len(records))
	for _, record := range records {
		name, err := dbdsn.HostName(record.Target)
		depth := strings.Count(name, ".") + 1
		if err != nil || depth < len(labels) || len(labels) == 2 && depth <= 2 || !strings.HasSuffix(name, "."+suffix) {
			return nil, errMongoTopology
		}
		address, err := dbdsn.TCPAddress(name, strconv.Itoa(int(record.Port)))
		if err != nil || dialer.CheckHost(name) != nil {
			return nil, errMongoTopology
		}
		if !slices.Contains(seeds, address) {
			seeds = append(seeds, address)
		}
	}
	txt, err := net.DefaultResolver.LookupTXT(ctx, host)
	if err != nil {
		var dns *net.DNSError
		if !errors.As(err, &dns) || !dns.IsNotFound {
			return nil, errMongoTopology
		}
	}
	if len(txt) > 1 || len(txt) == 1 && !mergeMongoTXT(target, txt[0]) {
		return nil, errMongoTopology
	}
	return seeds, nil
}

func mergeMongoTXT(target *dbdsn.Target, raw string) bool {
	if len(raw) == 0 || len(raw) > 1024 {
		return false
	}
	values, err := url.ParseQuery(strings.ReplaceAll(raw, ";", "&"))
	if err != nil {
		return false
	}
	seen := make(map[string]bool)
	for key, vals := range values {
		key = strings.ToLower(key)
		if seen[key] || len(vals) != 1 || vals[0] == "" || len(vals[0]) > 256 || strings.ContainsAny(vals[0], "\r\n\x00") {
			return false
		}
		seen[key] = true
		switch key {
		case "authsource":
			if !target.ExplicitAuthSource {
				target.AuthSource = vals[0]
			}
		case "loadbalanced":
			if vals[0] != "true" && vals[0] != "false" {
				return false
			}
			fallthrough
		case "replicaset":
			if _, present := target.Options[key]; !present {
				target.Options[key] = vals[0]
			}
		default:
			return false
		}
	}
	return len(seen) > 0
}
