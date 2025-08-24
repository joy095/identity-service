// github.com/joy095/identity/config/redis/redis.go
package redis

import (
	"context"
	"fmt"
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
func GetRedisClient(ctx context.Context) (*redis.Client, error) {
	redisOnce.Do(func() {
		redisURL := os.Getenv("REDIS_URL")
		if redisURL == "" {
			redisClient = nil
			return
		}

		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			redisClient = nil
			return
		}

		// Create client first
		redisClient = redis.NewClient(opt)

		// Then ping to check connectivity
		if _, err := redisClient.Ping(ctx).Result(); err != nil {
			log.Fatalf("Failed to connect to Redis: %v", err)
			redisClient = nil
			return
		}

		log.Println("Connected to Upstash Redis")
	})

	if redisClient == nil {
		return nil, fmt.Errorf("redis client not initialized; check REDIS_URL and connectivity")
	}
	return redisClient, nil
}

// CloseRedis closes the Redis connection
func CloseRedis() {
	if redisClient != nil {
		if err := redisClient.Close(); err != nil {
			log.Printf("Error closing Redis connection: %v", err)
		}
		log.Println("Redis connection closed")
	}
}
