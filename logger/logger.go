package logger

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// LoggerConfig holds the configuration for logging
type LoggerConfig struct {
	Filename    string
	MaxSize     int
	MaxBackups  int
	MaxAge      int
	Level       logrus.Level
	ServiceName string
}

// NewLogger initializes a new logger
func NewLogger(config LoggerConfig) *logrus.Logger {
	logger := logrus.New()

	// Configure log rotation
	logger.SetOutput(&lumberjack.Logger{
		Filename:   config.Filename,
		MaxSize:    config.MaxSize,    // MB
		MaxBackups: config.MaxBackups, // Number of old logs to keep
		MaxAge:     config.MaxAge,     // Days
		Compress:   true,              // Compress old logs
	})

	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
			logrus.FieldKeyFunc:  "function",
		},
	})

	logger.SetLevel(config.Level)

	return logger
}

// Initialize Loggers
var (
	InfoLogger  *logrus.Entry
	ErrorLogger *logrus.Entry
)

// InitLoggers initializes both info and error loggers
func InitLoggers() {
	// Ensure logs directory exists
	if _, err := os.Stat("logs"); os.IsNotExist(err) {
		os.Mkdir("logs", 0755) // Create logs directory if missing
	}

	serviceName := "identity-service"

	// Create base loggers
	infoBaseLogger := NewLogger(LoggerConfig{
		Filename:    "logs/info.log",
		MaxSize:     10,
		MaxBackups:  5,
		MaxAge:      30,
		Level:       logrus.InfoLevel,
		ServiceName: serviceName,
	})

	errorBaseLogger := NewLogger(LoggerConfig{
		Filename:    "logs/error.log",
		MaxSize:     10,
		MaxBackups:  5,
		MaxAge:      30,
		Level:       logrus.ErrorLevel,
		ServiceName: serviceName,
	})

	// Attach service name field
	InfoLogger = infoBaseLogger.WithField("identity-service", serviceName)
	ErrorLogger = errorBaseLogger.WithField("identity-service", serviceName)
}
