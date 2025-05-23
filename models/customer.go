package models

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	redisclient "github.com/joy095/identity/config/redis"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/utils"
)

// User Model
type Customer struct {
	ID              uuid.UUID
	Email           string
	RefreshToken    *string
	FirstName       string
	LastName        string
	IsVerifiedEmail bool
}

var ctx = context.Background()

// Create Customer function
func CreateCustomer(db *pgxpool.Pool, email string) (*User, string, string, error) {
	logger.InfoLogger.Info("CreateUser called on models")

	userID, err := GenerateUUIDv7()
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate UUIDv7: %v", err)
	}

	query := `INSERT INTO customers (id, email) 
              VALUES ($1, $2) RETURNING id`
	_, err = db.Exec(context.Background(), query, userID, email)
	if err != nil {
		return nil, "", "", err
	}

	user := &User{
		ID:    userID,
		Email: email,
	}

	return user, "", "", nil

}

func GetCustomerByEmail(db *pgxpool.Pool, email string) (*User, error) {
	var user User
	query := `SELECT id, email FROM customers WHERE email = $1`
	err := db.QueryRow(context.Background(), query, email).Scan(
		&user.ID, &user.Email,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// LoginUser authenticates a user and generates JWT + Refresh Token
func LoginCustomers(db *pgxpool.Pool, email string) (*User, string, string, error) {
	logger.InfoLogger.Info("LoginUser called on models")

	user, err := GetCustomerByEmail(db, email)
	if err != nil {
		return nil, "", "", err
	}

	accessToken, err := GenerateAccessToken(user.ID, time.Minute*60) // Access Token for 1 hour
	if err != nil {
		return nil, "", "", err
	}

	refreshToken, err := GenerateRefreshToken(user.ID, time.Hour*24*30) // Stronger Refresh Token for 30 days
	if err != nil {
		return nil, "", "", err
	}

	// Update refresh token in DB
	_, err = db.Exec(context.Background(), `UPDATE users SET refresh_token = $1 WHERE id = $2`, refreshToken, user.ID)
	if err != nil {
		return nil, "", "", err
	}

	user.RefreshToken = &refreshToken
	return user, accessToken, refreshToken, nil
}

func LoginCustomer(db *pgxpool.Pool, email string, otp string) (*Customer, string, string, error) {
	// logger.InfoLogger.Info("LoginCustomer (OTP verification) called on models") // Uncomment if logger

	// 1. Retrieve OTP hash from Redis
	redisKey := "otp:" + strings.ToLower(strings.TrimSpace(email)) // Match key format used in StoreOTP
	storedHash, err := redisclient.GetRedisClient().Get(ctx, redisKey).Result()
	if err != nil {

		return nil, "", "", errors.New("OTP expired or not found")
	}

	// 2. Verify the provided OTP
	providedHash := utils.HashOTP(strings.TrimSpace(otp)) // You need hashOTP function accessible here
	if providedHash != storedHash {

		return nil, "", "", errors.New("incorrect OTP")
	}

	// 3. Get customer by email

	user, err := GetCustomerByEmail(db, email)
	if err != nil {
		// GetCustomerByEmail already handles "not found" and other DB errors
		return nil, "", "", fmt.Errorf("failed to get customer after OTP verification: %w", err)
	}

	customer := &Customer{
		ID:    user.ID,
		Email: user.Email,
	}

	// 4. Delete OTP from Redis after successful verification
	if err := redisclient.GetRedisClient().Del(ctx, redisKey).Err(); err != nil {

	}

	// 5. Generate access token
	accessToken, err := GenerateAccessToken(customer.ID, time.Minute*60) // Access Token for 1 hour (example)
	if err != nil {
		// logger.ErrorLogger.Error("Failed to generate access token for user ID %s: %w", customer.ID, err) // Uncomment if logger
		return nil, "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// 6. Generate refresh token
	refreshToken, err := GenerateRefreshToken(customer.ID, time.Hour*24*30) // Refresh Token for 30 days (example)
	if err != nil {
		// logger.ErrorLogger.Error("Failed to generate refresh token for user ID %s: %w", customer.ID, err) // Uncomment if logger
		return nil, "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// 7. Update customer in DB (set is_verified_email to true and store refresh token)
	// Use a transaction if you need to ensure atomicity with other potential updates
	// Use transaction for atomic update
	tx, err := db.Begin(context.Background())
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(context.Background())

	_, err = tx.Exec(context.Background(),
		`UPDATE customers SET is_verified_email = TRUE, refresh_token = $1 WHERE id = $2`,
		refreshToken, customer.ID)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to update customer data after login: %w", err)
	}

	if err = tx.Commit(context.Background()); err != nil {
		return nil, "", "", fmt.Errorf("failed to commit transaction: %w", err)
	} // Update based on ID after fetching the user
	if err != nil {

		return nil, "", "", fmt.Errorf("failed to update customer data after login: %w", err)
	}

	// Update the customer object being returned with the new refresh token and verification status
	customer.IsVerifiedEmail = true
	customer.RefreshToken = &refreshToken // Assign the generated refresh token

	// logger.InfoLogger.Infof("Customer ID %s logged in successfully via OTP", customer.ID) // Uncomment if logger

	// 8. Return customer details, access token, and refresh token
	return customer, accessToken, refreshToken, nil
}
