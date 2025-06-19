// db/db.go
package db

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/joy095/identity/logger"

	"github.com/jackc/pgx/v5/pgxpool"
)

var DB *pgxpool.Pool

func Connect() {

	dsn := os.Getenv("DATABASE_URL")

	// Parse config to allow setting pool options
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		logger.ErrorLogger.Error("Unable to parse database URL:", err)
		fmt.Println("Unable to parse database URL:", err)
		os.Exit(1)
	}

	// Optional: Configure pool settings for better resilience
	// These are good defaults, but you can adjust based on your needs.
	cfg.MaxConns = 10                      // Maximum number of connections in the pool
	cfg.MinConns = 2                       // Minimum number of idle connections to keep open
	cfg.MaxConnLifetime = time.Hour        // Max duration a connection can be used
	cfg.MaxConnIdleTime = 30 * time.Minute // Max duration a connection can be idle before closing

	pool, err := pgxpool.NewWithConfig(context.Background(), cfg) // Use NewWithConfig
	if err != nil {
		logger.ErrorLogger.Error("Unable to connect to database:", err)
		fmt.Println("Unable to connect to database:", err)
		os.Exit(1)
	}

	// Ping the database to verify the connection
	err = pool.Ping(context.Background())
	if err != nil {
		pool.Close() // Close the pool immediately if ping fails
		logger.ErrorLogger.Error("Could not ping database:", err)
		fmt.Println("Could not ping database:", err)
		os.Exit(1)
	}

	DB = pool
	logger.InfoLogger.Info("Connected to PostgreSQL!")
	fmt.Println("Connected to PostgreSQL!")
}

// Close disconnects the database pool.
func Close() {
	if DB != nil {
		DB.Close()
		logger.InfoLogger.Info("Disconnected from PostgreSQL!")
		fmt.Println("Disconnected from PostgreSQL!")
	}
}
