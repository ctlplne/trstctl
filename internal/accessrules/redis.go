// SPDX-License-Identifier: BUSL-1.1
package accessrules

import "bytes"

var redisOperationNames = []string{"APPEND", "DECR", "DECRBY", "DEL", "EVAL", "EVALSHA", "EXPIRE", "FCALL", "FCALL_RO", "GET", "GETDEL", "HDEL", "HGET", "HMGET", "HMSET", "HSET", "INCR", "INCRBY", "LPOP", "LPUSH", "MGET", "MSET", "PERSIST", "PEXPIRE", "RENAME", "RENAMENX", "RPOP", "RPUSH", "SADD", "SET", "SREM", "SISMEMBER", "SMEMBERS", "TTL", "UNLINK", "ZADD", "ZREM"}

// RedisOperation accepts a command-name slice only. Keys, values and credentials
// cannot be parameters of this classifier; the returned string is public static
// vocabulary. Script/function bodies are arguments and are not inspected.
func RedisOperation(name []byte) string {
	if len(name) < 1 || len(name) > 64 {
		return ""
	}
	for _, c := range name {
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return ""
		}
	}
	for _, op := range redisOperationNames {
		if bytes.EqualFold(name, []byte(op)) {
			return op
		}
	}
	return ""
}
