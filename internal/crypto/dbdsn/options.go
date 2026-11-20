// SPDX-License-Identifier: BUSL-1.1

package dbdsn

import (
	"bytes"
	"strconv"
	"strings"
	"time"
)

func (p *profile) option(key string, value []byte, fromQuery bool) (string, []byte, error) {
	if !fromQuery {
		switch key {
		case "user", "password", "database":
			return key, value, nil
		}
	}
	if len(value) > 4096 && key != "password" {
		return "", nil, ErrInvalid
	}
	var admitted bool
	switch p.driver {
	case Postgres:
		key, value, admitted = p.postgresOption(key, value, fromQuery)
	case Mongo:
		key, admitted = p.mongoOption(strings.ToLower(key), value)
		if key == "connect" {
			key = "directconnection"
			switch string(value) {
			case "direct":
				value, admitted = []byte("true"), true
			case "automatic":
				value, admitted = []byte("false"), true
			}
		}
	case MySQL:
		admitted = p.mysqlOption(key, value)
	case Oracle:
		key, value, admitted = oracleOption(strings.ToUpper(key), value)
	case MSSQL:
		key, admitted = p.mssqlOption(strings.ToLower(key), value)
	case HANA:
		key, admitted = p.hanaOption(key, value)
	}
	if !admitted || p.driver == Postgres && p.purpose == Gateway && !postgresGatewayOption(key, string(value)) {
		return "", nil, ErrOption
	}
	return key, value, nil
}

func (p *profile) postgresOption(key string, value []byte, uri bool) (string, []byte, bool) {
	switch key {
	case "user", "password", "host", "port", "database":
		return key, value, true
	case "dbname":
		return "database", value, true
	case "ssl":
		return "sslmode", []byte("require"), uri && bytes.Equal(value, []byte("true"))
	case "sslmode":
		return key, value, oneOf(value, "disable", "allow", "prefer", "require", "verify-ca", "verify-full")
	case "sslrootcert":
		return "ca_file", value, p.purpose == Admin && len(value) > 0 || bytes.Equal(value, []byte("system"))
	case "sslnegotiation":
		return key, value, oneOf(value, "postgres", "direct")
	case "connect_timeout":
		return key, value, seconds(value, 60)
	case "target_session_attrs":
		return key, value, oneOf(value, "any", "read-write", "read-only", "primary", "standby", "prefer-standby")
	case "application_name", "client_encoding", "DateStyle", "datestyle", "TimeZone", "timezone", "extra_float_digits", "IntervalStyle", "intervalstyle":
		return strings.ToLower(key), value, identifier(string(value), 512)
	case "search_path", "statement_timeout", "lock_timeout":
		return strings.ToLower(key), value, identifier(string(value), 512)
	default:
		return "", nil, false
	}
}

func (p *profile) mongoOption(key string, value []byte) (string, bool) {
	switch key {
	case "authsource", "replicaset":
		return key, len(value) != 0 && identifier(string(value), 256)
	case "authmechanism":
		return key, oneOf(value, "SCRAM-SHA-256") || p.purpose != Gateway && oneOf(value, "SCRAM-SHA-1")
	case "tls", "ssl":
		return "tls", oneOf(value, "true", "false")
	case "tlscafile":
		return "ca_file", p.purpose == Admin && len(value) > 0
	case "directconnection", "retryreads", "retrywrites":
		return key, oneOf(value, "true", "false")
	case "loadbalanced":
		return key, oneOf(value, "false") || p.purpose != Gateway && oneOf(value, "true")
	case "connect":
		return key, false // legacy topology spelling is normalized by option
	case "connecttimeoutms", "serverselectiontimeoutms", "timeoutms", "maxidletimems":
		return key, seconds(value, 60000)
	case "maxpoolsize", "minpoolsize":
		return key, seconds(value, 32)
	case "appname":
		return key, identifier(string(value), 128)
	default:
		return "", false
	}
}

func (p *profile) mysqlOption(key string, value []byte) bool {
	if p.purpose == Gateway {
		return key == "tls" && oneOf(value, "false") || key == "parseTime" && oneOf(value, "true", "false", "0", "1")
	}
	switch key {
	case "allowAllFiles":
		return oneOf(value, "false", "0")
	case "allowNativePasswords", "checkConnLiveness", "clientFoundRows", "columnsWithAlias", "compress", "interpolateParams", "parseTime", "rejectReadOnly":
		return oneOf(value, "true", "false", "1", "0")
	case "charset", "collation":
		return len(value) > 0 && len(value) <= 128 && asciiWords(value, "_")
	case "loc":
		return oneOf(value, "UTC", "Local")
	case "timeout", "readTimeout", "writeTimeout", "timeTruncate":
		return boundedDuration(value, time.Minute)
	case "maxAllowedPacket":
		return seconds(value, 64<<20)
	case "tls":
		return len(value) > 0 && len(value) <= 64 && asciiWords(value, "-_")
	default:
		return false
	}
}

func oracleOption(key string, value []byte) (string, []byte, bool) {
	switch key {
	case "SSL", "SSL VERIFY":
		text := strings.ToLower(string(value))
		switch text {
		case "true", "enable", "enabled":
			return key, []byte("true"), true
		case "false", "disable", "disabled":
			return key, []byte("false"), true
		}
	case "TIMEOUT", "READ TIMEOUT", "SOCKET TIMEOUT":
		return "TIMEOUT", value, seconds(value, 60)
	case "CONNECT TIMEOUT", "CONNECTION TIMEOUT":
		return "CONNECT TIMEOUT", value, seconds(value, 60)
	case "ENCRYPTION", "DATA INTEGRITY":
		return key, value, oneOfFold(value, "ACCEPTED", "REJECTED", "REQUESTED", "REQUIRED")
	case "PREFETCH_ROWS":
		return key, value, seconds(value, 10000)
	case "LANGUAGE", "TERRITORY", "CHARSET", "CLIENT CHARSET":
		if key == "CLIENT CHARSET" {
			key = "CHARSET"
		}
		return key, value, len(value) > 0 && len(value) <= 128 && asciiWords(value, "_ -")
	}
	return "", nil, false
}

func (p *profile) mssqlOption(key string, value []byte) (string, bool) {
	switch key {
	case "database":
		return key, identifier(string(value), 256)
	case "encrypt":
		return key, oneOfFold(value, "mandatory", "yes", "1", "t", "true", "disable", "strict", "optional", "no", "0", "f", "false")
	case "trustservercertificate", "disableretry", "multisubnetfailover":
		return key, oneOfFold(value, "true", "false", "yes", "no", "t", "f", "1", "0")
	case "hostnameincertificate":
		_, err := HostName(string(value))
		return key, err == nil
	case "connection timeout", "dial timeout", "keepalive":
		return key, seconds(value, 60)
	case "applicationintent":
		return key, oneOfFold(value, "readonly", "readwrite")
	case "app name", "workstation id":
		return key, identifier(string(value), 128)
	case "packet size":
		return key, seconds(value, 32767)
	case "certificate":
		return "ca_file", p.purpose == Admin && len(value) > 0
	case "timezone":
		return key, oneOf(value, "UTC", "Local")
	default:
		return "", false
	}
}

func (p *profile) hanaOption(key string, value []byte) (string, bool) {
	switch key {
	case "defaultSchema":
		return key, len(value) > 0 && identifier(string(value), 256)
	case "timeout", "pingInterval":
		return key, seconds(value, 60)
	case "TLSRootCAFile":
		return "ca_file", p.purpose == Admin && len(value) > 0
	case "TLSServerName":
		_, err := HostName(string(value))
		return key, err == nil
	case "TLSInsecureSkipVerify":
		return key, oneOf(value, "false")
	default:
		return "", false
	}
}

func seconds(value []byte, max uint64) bool {
	n, err := strconv.ParseUint(string(value), 10, 32)
	return err == nil && n <= max
}

func boundedDuration(value []byte, max time.Duration) bool {
	d, err := time.ParseDuration(string(value))
	return err == nil && d >= 0 && d <= max
}

func oneOf(value []byte, valid ...string) bool {
	for _, v := range valid {
		if bytes.Equal(value, []byte(v)) {
			return true
		}
	}
	return false
}

func oneOfFold(value []byte, valid ...string) bool {
	for _, v := range valid {
		if bytes.EqualFold(value, []byte(v)) {
			return true
		}
	}
	return false
}

func asciiWords(value []byte, punctuation string) bool {
	for _, c := range value {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune(punctuation, rune(c)) {
			return false
		}
	}
	return true
}
