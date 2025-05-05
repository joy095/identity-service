package db

import (
	"context"
	"fmt"
	"os"

	"github.com/joy095/identity/config"
	"github.com/joy095/identity/logger"

	"github.com/jackc/pgx/v5/pgxpool"
)

var DB *pgxpool.Pool

func Connect() {
	config.LoadEnv()

	dsn := os.Getenv("DATABASE_URL")

	if _, err := pgxpool.ParseConfig(dsn); err != nil {
		logger.ErrorLogger.Error("Unable to parse database URL:", err)
		fmt.Println("Unable to parse database URL:", err)
		os.Exit(1)
	}

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		logger.ErrorLogger.Error("Unable to connect to database:", err)

		fmt.Println("Unable to connect to database:", err)
		os.Exit(1)
	}

	DB = pool
	logger.InfoLogger.Info("Connected to PostgreSQL!")

	fmt.Println("Connected to PostgreSQL!")
}
