// github.com/joy095/identity/config/redis/redis.go
package redis

import (
	"context"
	"crypto/tls"
	"log"
	"os"
	"sync"

	"github.com/redis/go-redis/v9"
)

var (
	redisClient *redis.Client
	redisOnce   sync.Once
)

// GetRedisClient returns a singleton Redis client
func GetRedisClient(ctx context.Context) *redis.Client {
	redisOnce.Do(func() {
		redisURL := os.Getenv("REDIS_URL")
		if redisURL == "" {
			log.Fatal("REDIS_URL environment variable is not set")
		}

		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			log.Fatalf("Failed to parse REDIS_URL: %v", err)
		}

		// Ensure TLS for Upstash
		if opt.TLSConfig == nil {
			opt.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}

		redisClient = redis.NewClient(opt)

		if _, err := redisClient.Ping(ctx).Result(); err != nil {
			log.Fatalf("Failed to connect to Redis: %v", err)
		}
		log.Println("Connected to Upstash Redis")
	})

	return redisClient
}

// CloseRedis closes the Redis connection
func CloseRedis() {
	if redisClient != nil {
		if err := redisClient.Close(); err != nil {
			log.Printf("Error closing Redis connection: %v", err)
		}
		redisClient = nil
		log.Println("Redis connection closed")
	}
}
