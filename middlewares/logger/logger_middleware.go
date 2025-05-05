package logger_middleware

import (
	"time"

	"github.com/joy095/identity/logger"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// GinLogger is a middleware that logs requests
func GinLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()
		c.Next()
		duration := time.Since(startTime)

		statusCode := c.Writer.Status()
		logEntry := logger.InfoLogger.WithFields(logrus.Fields{
			"status":     statusCode,
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"ip":         c.ClientIP(),
			"user-agent": c.Request.UserAgent(),
			"duration":   duration.String(),
		})

		if statusCode >= 400 {
			logger.ErrorLogger.WithFields(logrus.Fields{
				"error": c.Errors.String(),
			}).Error("Request failed")
		} else {
			logEntry.Info("Request processed successfully")
		}
	}
}
