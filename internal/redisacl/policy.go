// SPDX-License-Identifier: BUSL-1.1

// Package redisacl compiles a deliberately small, stable Redis command grant.
// It never accepts raw ACL rules or categories, whose meaning can expand when
// Redis or a module is upgraded.
package redisacl

import (
	"errors"
	"fmt"
	"strings"
)

// Role is the operator-reviewed authority for one dynamic Redis lease role.
// Each key prefix is literal; Compile adds the only trailing wildcard.
type Role struct {
	KeyPrefixes []string `json:"key_prefixes"`
	Commands    []string `json:"commands"`
}

var allowedCommands = map[string]struct{}{
	"get": {}, "mget": {}, "exists": {}, "ttl": {}, "pttl": {}, "type": {}, "strlen": {},
	"hget": {}, "hgetall": {}, "hmget": {}, "hexists": {}, "lrange": {},
	"scard": {}, "smembers": {}, "zrange": {},
	"set": {}, "mset": {}, "del": {}, "unlink": {}, "expire": {}, "pexpire": {},
	"incr": {}, "incrby": {}, "decr": {}, "decrby": {}, "hset": {}, "hdel": {},
	"lpush": {}, "rpush": {}, "lpop": {}, "rpop": {}, "sadd": {}, "srem": {},
	"zadd": {}, "zrem": {},
}

// Compile returns only literal key-prefix patterns and explicit safe commands.
// PING is added by the backend so ordinary clients can probe a connection.
func Compile(role Role) ([]string, error) {
	if len(role.KeyPrefixes) == 0 || len(role.KeyPrefixes) > 8 {
		return nil, errors.New("redis ACL role needs 1-8 key prefixes")
	}
	if len(role.Commands) == 0 || len(role.Commands) > 32 {
		return nil, errors.New("redis ACL role needs 1-32 allowed commands")
	}
	rules := make([]string, 0, len(role.KeyPrefixes)+len(role.Commands))
	seenPrefixes := make(map[string]bool, len(role.KeyPrefixes))
	for _, prefix := range role.KeyPrefixes {
		if len(prefix) == 0 || len(prefix) > 128 || !literalPrefix(prefix) {
			return nil, fmt.Errorf("redis ACL key prefix %q must be 1-128 literal ASCII namespace characters", prefix)
		}
		if seenPrefixes[prefix] {
			return nil, fmt.Errorf("redis ACL duplicate key prefix %q", prefix)
		}
		seenPrefixes[prefix] = true
		rules = append(rules, "~"+prefix+"*")
	}
	seenCommands := make(map[string]bool, len(role.Commands))
	for _, command := range role.Commands {
		name := strings.ToLower(command)
		if _, allowed := allowedCommands[name]; !allowed {
			return nil, fmt.Errorf("redis ACL command %q is outside the safe command set", command)
		}
		if seenCommands[name] {
			return nil, fmt.Errorf("redis ACL duplicate command %q", command)
		}
		seenCommands[name] = true
		rules = append(rules, "+"+name)
	}
	return rules, nil
}

func literalPrefix(prefix string) bool {
	for i := 0; i < len(prefix); i++ {
		character := prefix[i]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == ':' || character == '_' || character == '-' ||
			character == '.' || character == '/' {
			continue
		}
		return false
	}
	return true
}
