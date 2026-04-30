// ========== REDIS PIPELINE FOR IDS AI BACKEND ==========
//
// This code integrates into the Rihno Dealer to push metrics into Redis
// in the exact key schema expected by the Python IDS Zero-Day Detection API.
//
// Redis Key Schema (must match redis_store.py):
//   ids:agents                           SET    — all registered agent keys
//   ids:{email}:{agent}:stream           STREAM — raw metrics (capped at 5000)
//   ids:{email}:{agent}:latest           STRING — latest metric JSON snapshot
//   ids:global:stats                     HASH   — global counters
//
// Add to imports:
//   "github.com/redis/go-redis/v9"
//   "strings"
//
// Add to global vars:
//   var redisClient *redis.Client
//

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// ── Redis config constants ──────────────────────────────────────────────────

const (
	redisKeyPrefix = "ids"
	streamMaxLen   = 5000 // Max entries per agent stream (matches Python STREAM_MAXLEN)
)

// ── Redis client (global, set in main) ──────────────────────────────────────

var redisClient *redis.Client

// ── Initialization ──────────────────────────────────────────────────────────

// initRedisClient creates and tests a Redis connection.
// Call once in main() before accepting agent connections.
//
// Environment variables:
//
//	REDIS_URL   — full Redis URL (e.g. redis://:password@host:6379/0)
//	REDIS_HOST  — host (default: my_rihno_redis)
//	REDIS_PORT  — port (default: 6379)
//	REDIS_PASS  — password (default: empty)
//	REDIS_DB    — database number (default: 0)
func initRedisClient() *redis.Client {
	// Prefer REDIS_URL if set (e.g. for managed Redis)
	redisURL := os.Getenv("REDIS_URL")
	if redisURL != "" {
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			log.Fatalf("[Redis] Failed to parse REDIS_URL: %v", err)
		}
		client := redis.NewClient(opt)
		pingRedis(client)
		return client
	}

	// Otherwise build from individual env vars
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		host = "my_rihno_redis" // Docker service name
	}

	port := os.Getenv("REDIS_PORT")
	if port == "" {
		port = "6379"
	}

	password := os.Getenv("REDIS_PASS")

	db := 0
	if dbStr := os.Getenv("REDIS_DB"); dbStr != "" {
		fmt.Sscanf(dbStr, "%d", &db)
	}

	client := redis.NewClient(&redis.Options{
		Addr:         host + ":" + port,
		Password:     password,
		DB:           db,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     10,
		MinIdleConns: 2,
	})

	pingRedis(client)
	return client
}

func pingRedis(client *redis.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		log.Printf("[Redis] WARNING: Redis ping failed: %v (will retry on first write)", err)
	} else {
		log.Println("[Redis] Connected successfully")
	}
}

// ── Key helpers (must match Python redis_store.py) ──────────────────────────

// sanitizeKeyPart replaces characters that could break Redis key structure.
// Mirrors Python: safe_email = email.replace(":", "_")
func sanitizeKeyPart(s string) string {
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

// makeRedisKey builds a key like "ids:sakibdalal73@gmail.com:Mac:stream"
// This MUST match the Python _agent_key() + _key() methods exactly.
func makeRedisKey(email, agent string, suffix string) string {
	safeEmail := sanitizeKeyPart(email)
	safeAgent := sanitizeKeyPart(agent)
	return fmt.Sprintf("%s:%s:%s:%s", redisKeyPrefix, safeEmail, safeAgent, suffix)
}

func makeGlobalKey(suffix string) string {
	return fmt.Sprintf("%s:global:%s", redisKeyPrefix, suffix)
}

// ── Core pipeline function ──────────────────────────────────────────────────

// sendToRedis pushes a MetricsPayload into Redis for the IDS AI backend.
//
// It performs 4 operations in a single Redis pipeline (round-trip):
//  1. XADD to the agent's stream (capped at streamMaxLen)
//  2. SET the latest snapshot for fast lookups
//  3. SADD the agent to the global registry
//  4. HINCRBY the global processed counter
//
// This function is non-blocking on failure — a Redis outage should not
// stop the dealer from processing metrics through other pipelines.
func sendToRedis(payload *MetricsPayload) error {
	if redisClient == nil {
		return fmt.Errorf("redis client not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	email := payload.Email
	agent := payload.AgentName

	// Marshal the full payload to JSON (same format Python expects)
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload for Redis: %w", err)
	}

	// Build the agent ID string (must match Python: f"{safe_email}:{safe_agent}")
	agentID := fmt.Sprintf("%s:%s", sanitizeKeyPart(email), sanitizeKeyPart(agent))

	// Keys
	streamKey := makeRedisKey(email, agent, "stream")
	latestKey := makeRedisKey(email, agent, "latest")
	agentsKey := fmt.Sprintf("%s:agents", redisKeyPrefix)
	globalStatsKey := makeGlobalKey("stats")

	// Execute all 4 operations in a single pipeline (1 round-trip)
	pipe := redisClient.Pipeline()

	// 1. Append to agent's metric stream
	//    XADD ids:{email}:{agent}:stream MAXLEN ~ 5000 * data <json>
	pipe.XAdd(ctx, &redis.XAddArgs{
		Stream: streamKey,
		MaxLen: streamMaxLen,
		Approx: true, // ~ for performance (matches Python approximate=True)
		Values: map[string]interface{}{
			"data": string(payloadJSON),
		},
	})

	// 2. Overwrite latest snapshot
	//    SET ids:{email}:{agent}:latest <json>
	pipe.Set(ctx, latestKey, string(payloadJSON), 0)

	// 3. Register agent in global set
	//    SADD ids:agents {email}:{agent}
	pipe.SAdd(ctx, agentsKey, agentID)

	// 4. Increment global counter
	//    HINCRBY ids:global:stats total_processed 1
	pipe.HIncrBy(ctx, globalStatsKey, "total_processed", 1)

	// Execute pipeline
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("redis pipeline exec failed: %w", err)
	}

	log.Printf("[Redis] Pushed metrics for %s:%s to stream %s", email, agent, streamKey)
	return nil
}

// ── Health check ────────────────────────────────────────────────────────────

// redisHealthCheck verifies Redis is reachable. Used by the /health endpoint.
func redisHealthCheck() bool {
	if redisClient == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return redisClient.Ping(ctx).Err() == nil
}

// ── Optional: Query helpers (for HTTP endpoints) ────────────────────────────

// getRedisAgents returns all registered agent IDs from Redis.
func getRedisAgents() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	agentsKey := fmt.Sprintf("%s:agents", redisKeyPrefix)
	members, err := redisClient.SMembers(ctx, agentsKey).Result()
	if err != nil {
		return nil, err
	}
	return members, nil
}

// getRedisGlobalStats returns global IDS statistics from Redis.
func getRedisGlobalStats() (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	statsKey := makeGlobalKey("stats")
	return redisClient.HGetAll(ctx, statsKey).Result()
}
