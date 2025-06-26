package middleware

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	db "github.com/joy095/identity/config/redis" // Assuming this imports your Redis client
	"github.com/ulule/limiter/v3"
	ginmiddleware "github.com/ulule/limiter/v3/drivers/middleware/gin"
	redisstore "github.com/ulule/limiter/v3/drivers/store/redis"
)

// Example route using NewRateLimiter
// r.GET("/single-rate-limited", middlewares.NewRateLimiter("10-2m", "singleRateRoute"), func(c *gin.Context) {
// 	c.JSON(200, gin.H{
// 		"message": "This route is rate-limited to 10 requests per 2 minutes.",
// 	})
// })

// Example route using CombinedRateLimiter
// r.GET("/combined-rate-limited", middlewares.CombinedRateLimiter("combinedRateRoute", "5-1m", "20-10m"), func(c *gin.Context) {
// 	c.JSON(200, gin.H{
// 		"message": "This route is rate-limited to 5 requests per minute and 20 requests per 10 minutes.",
// 	})
// })

// getUserIDFromContext is a placeholder function to get the user ID.
// You should replace this with your actual logic to extract the user ID from the Gin context.
// For example, from JWT claims, session, or a request header.
func getUserIDFromContext(c *gin.Context) string {
	// In a real application, you'd extract the user ID securely.
	// For demonstration, let's assume a header "X-User-ID"
	userID := c.GetHeader("X-User-ID")
	if userID == "" {
		// Fallback or error handling if user ID is not found.
		// For a robust system, you might want to return an error or a generic ID.
		// For this example, we'll use "anonymous" for unauthenticated requests.
		return "anonymous"
	}
	return userID
}

// createRedisStore creates a Redis-backed rate limiter store with a route-specific and user-specific prefix,
// and sets the expiration based on the rate's period.
func createRedisStore(routeID string, period time.Duration) (limiter.Store, error) {
	rdb := db.GetRedisClient()

	store, err := redisstore.NewStoreWithOptions(rdb, limiter.StoreOptions{
		Prefix:   fmt.Sprintf("rate_limiter:%s", routeID), // This prefix will be combined with the key function
		MaxRetry: 3,
		// CleanUpInterval ensures that the Redis keys are cleaned up after the rate's period.
		// This is crucial for correctly implementing time-windowed rate limits.
		CleanUpInterval: period,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create redis store for route %s: %w", routeID, err)
	}
	return store, nil
}

// ParseCustomRate allows formats like "10-2m", "30-20m", "5-1h", etc.
// ParseCustomRate allows formats like "10-2m", "30-20m", "5-1h", "20-10s", etc.
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

	switch {
	case strings.HasSuffix(durationStr, "s"):
		seconds, err := strconv.Atoi(strings.TrimSuffix(durationStr, "s"))
		if err != nil {
			return limiter.Rate{}, fmt.Errorf("invalid seconds duration: %v", err)
		}
		period = time.Duration(seconds) * time.Second

	case strings.HasSuffix(durationStr, "m"):
		minutes, err := strconv.Atoi(strings.TrimSuffix(durationStr, "m"))
		if err != nil {
			return limiter.Rate{}, fmt.Errorf("invalid minutes duration: %v", err)
		}
		period = time.Duration(minutes) * time.Minute

	case strings.HasSuffix(durationStr, "h"):
		hours, err := strconv.Atoi(strings.TrimSuffix(durationStr, "h"))
		if err != nil {
			return limiter.Rate{}, fmt.Errorf("invalid hours duration: %v", err)
		}
		period = time.Duration(hours) * time.Hour

	default:
		return limiter.Rate{}, fmt.Errorf("unsupported period: %s", durationStr)
	}

	return limiter.Rate{
		Period: period,
		Limit:  int64(limit),
	}, nil
}

// NewRateLimiter creates middleware with custom periods like "10-2m" for a specific route and user.
func NewRateLimiter(rateStr, routeID string) gin.HandlerFunc {
	rate, err := ParseCustomRate(rateStr)
	if err != nil {
		log.Printf("Error parsing rate for route %s: %v", routeID, err)
		// Return a fallback middleware that just passes through
		return func(c *gin.Context) {
			c.Next()
		}
	}

	// Pass the period to createRedisStore for proper expiration
	store, err := createRedisStore(routeID, rate.Period)
	if err != nil {
		log.Printf("Error creating Redis store for route %s: %v", routeID, err)
		// Return a fallback middleware that just passes through
		return func(c *gin.Context) {
			c.Next()
		}
	}

	// Create a limiter instance
	limiterInstance := limiter.New(store, rate)

	// Create a Gin middleware that uses a custom key function to identify the user
	return ginmiddleware.NewMiddleware(limiterInstance, ginmiddleware.WithKeyGetter(func(c *gin.Context) string {
		userID := getUserIDFromContext(c)
		// The key for the rate limiter will be "routeID:userID"
		// The prefix "rate_limiter:routeID" is already handled by the store options.
		// So here, we just need the user ID as the key part.
		return userID
	}))
}

// CombinedRateLimiter accepts multiple custom rate strings for a specific route and user.
func CombinedRateLimiter(routeID string, rateStrings ...string) gin.HandlerFunc {
	// We will create a slice of individual rate limiter middlewares.
	// Each individual limiter will handle its own rate and expiration.
	middlewares := make([]gin.HandlerFunc, len(rateStrings))
	for i, rateStr := range rateStrings {
		// Each rate string corresponds to a separate rate limiter instance
		// for the same route and user.
		middlewares[i] = NewRateLimiter(rateStr, fmt.Sprintf("%s_%d", routeID, i)) // Append index to routeID for unique keys for combined limits
	}

	// Return a single Gin handler that runs all the individual rate limiter middlewares.
	// If any of the rate limits are exceeded, the request will be aborted.
	return func(c *gin.Context) {
		for _, mw := range middlewares {
			mw(c)
			// If any middleware aborts the request (e.g., due to rate limit exceeded), stop processing.
			if c.IsAborted() {
				return
			}
		}
		// If all middlewares pass, continue to the next handler in the chain.
		c.Next()
	}
}
