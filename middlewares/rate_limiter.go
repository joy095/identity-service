package middleware

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	db "github.com/joy095/identity/config/redis"
	"github.com/ulule/limiter/v3"
	ginmiddleware "github.com/ulule/limiter/v3/drivers/middleware/gin"
	redisstore "github.com/ulule/limiter/v3/drivers/store/redis"
)

// Example route using NewRateLimiter
// r.GET("/single-rate-limited", middlewares.NewRateLimiter("10-2m", "singleRateRoute"), func(c *gin.Context) {
//     c.JSON(200, gin.H{
//         "message": "This route is rate-limited to 10 requests per 2 minutes.",
//     })
// })

// Example route using CombinedRateLimiter
// r.GET("/combined-rate-limited", middlewares.CombinedRateLimiter("combinedRateRoute", "5-1m", "20-10m"), func(c *gin.Context) {
//     c.JSON(200, gin.H{
//         "message": "This route is rate-limited to 5 requests per minute and 20 requests per 10 minutes.",
//     })
// })

// createRedisStore creates a Redis-backed rate limiter store with a route-specific prefix
func createRedisStore(routeID string) (limiter.Store, error) {
	rdb := db.GetRedisClient()

	// Use a route-specific prefix to ensure rate limits are tracked separately
	store, err := redisstore.NewStoreWithOptions(rdb, limiter.StoreOptions{
		Prefix:   fmt.Sprintf("rate_limiter:%s", routeID),
		MaxRetry: 3,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create redis store for route %s: %w", routeID, err)
	}
	return store, nil
}

// ParseCustomRate allows formats like "10-2m", "30-20m", "5-1h", etc.
func ParseCustomRate(rateStr string) (limiter.Rate, error) {
	parts := strings.Split(rateStr, "-")
	if len(parts) != 2 {
		return limiter.Rate{}, fmt.Errorf("invalid rate format: %s", rateStr)
	}
	limit, err := strconv.Atoi(parts[0])
	if err != nil {
		return limiter.Rate{}, fmt.Errorf("invalid limit: %s", parts[0])
	}

	durationStr := parts[1]
	var period time.Duration

	if strings.HasSuffix(durationStr, "m") {
		minutes, err := strconv.Atoi(strings.TrimSuffix(durationStr, "m"))
		if err != nil {
			return limiter.Rate{}, err
		}
		period = time.Duration(minutes) * time.Minute
	} else if strings.HasSuffix(durationStr, "h") {
		hours, err := strconv.Atoi(strings.TrimSuffix(durationStr, "h"))
		if err != nil {
			return limiter.Rate{}, err
		}
		period = time.Duration(hours) * time.Hour
	} else {
		return limiter.Rate{}, fmt.Errorf("unsupported period: %s", durationStr)
	}

	return limiter.Rate{
		Period: period,
		Limit:  int64(limit),
	}, nil
}

// NewRateLimiter creates middleware with custom periods like "10-2m" for a specific route
func NewRateLimiter(rateStr, routeID string) gin.HandlerFunc {
	rate, err := ParseCustomRate(rateStr)
	if err != nil {
		log.Printf("Error parsing rate for route %s: %v", routeID, err)
		// Return a fallback middleware that just passes through
		return func(c *gin.Context) {
			c.Next()
		}
	}

	store, err := createRedisStore(routeID)
	if err != nil {
		log.Printf("Error creating Redis store for route %s: %v", routeID, err)
		// Return a fallback middleware that just passes through
		return func(c *gin.Context) {
			c.Next()
		}
	}

	limiterInstance := limiter.New(store, rate)
	return ginmiddleware.NewMiddleware(limiterInstance)
}

// CombinedRateLimiter accepts multiple custom rate strings for a specific route
func CombinedRateLimiter(routeID string, rateStrings ...string) gin.HandlerFunc {
	middlewares := make([]gin.HandlerFunc, len(rateStrings))
	for i, rateStr := range rateStrings {
		middlewares[i] = NewRateLimiter(rateStr, routeID)
	}
	return func(c *gin.Context) {
		for _, mw := range middlewares {
			mw(c)
			if c.IsAborted() {
				return
			}
		}
	}
}
