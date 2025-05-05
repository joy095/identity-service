package redis

import (
	"context"
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
func GetRedisClient() *redis.Client {
	redisOnce.Do(func() {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     os.Getenv("REDIS_HOST"),
			Password: os.Getenv("REDIS_PASSWORD"),
			DB:       0,
			OnConnect: func(ctx context.Context, cn *redis.Conn) error {
				log.Println("Connected to Redis")
				return nil
			},
		})

		// Test the connection
		if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
			log.Printf("Warning: Redis connection failed: %v", err)
			// We keep the client, but operations will fail
		}
	})

	return redisClient
}

// CloseRedis closes the Redis connection
func CloseRedis() {
	if redisClient != nil {
		if err := redisClient.Close(); err != nil {
			log.Printf("Error closing Redis connection: %v", err)
		}
	}
}
