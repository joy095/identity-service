package db

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
)

var DB *pgxpool.Pool

func Connect() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		logger.ErrorLogger.Error("DATABASE_URL not set")
		fmt.Println("DATABASE_URL not set")
		os.Exit(1)
	}

	// Parse and configure the pool
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		logger.ErrorLogger.Errorf("Unable to parse DATABASE_URL: %v", err)
		os.Exit(1)
	}

	// Recommended defaults
	cfg.MaxConns = 10
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 30 * time.Minute

	start := time.Now()

	// Context timeout ensures we don’t block for 30–40 seconds
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		logger.ErrorLogger.Errorf("Database connection error: %v", err)
		fmt.Println("Database connection error:", err)
		os.Exit(1)
	}

	// Try pinging once, but don’t block server startup
	go func() {
		pingCtx, pingCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer pingCancel()

		if err := pool.Ping(pingCtx); err != nil {
			logger.ErrorLogger.Warnf("Database cold start or unreachable: %v", err)
			fmt.Println("Database cold start or unreachable:", err)
		} else {
			logger.InfoLogger.Infof("Database ready (ping ok in %v)", time.Since(start))
			fmt.Println("Database ready (ping ok in):", time.Since(start))
		}
	}()

	DB = pool
	logger.InfoLogger.Info("Connected to PostgreSQL pool (async ping).")
	fmt.Println("Connected to PostgreSQL pool (async ping).")
}

func Close() {
	if DB != nil {
		DB.Close()
		logger.InfoLogger.Info("Disconnected from PostgreSQL.")
		fmt.Println("Disconnected from PostgreSQL.")
	}
}
