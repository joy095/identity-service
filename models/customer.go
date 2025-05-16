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
		// Handle Redis errors (e.g., key not found, connection issues)
		// logger.ErrorLogger.Error("Failed to retrieve OTP from Redis: " + err.Error()) // Uncomment if logger
		// Return a generic error to the user for security
		return nil, "", "", errors.New("OTP expired or not found")
	}

	// 2. Verify the provided OTP
	providedHash := utils.HashOTP(strings.TrimSpace(otp)) // You need hashOTP function accessible here
	if providedHash != storedHash {
		// logger.ErrorLogger.Error("Incorrect OTP provided for email: " + email) // Uncomment if logger
		// Consider adding rate limiting here to prevent brute force
		return nil, "", "", errors.New("incorrect OTP")
	}

	// 3. Get customer by email
	// It's good practice to fetch the user *after* verifying the OTP to
	// reduce unnecessary database lookups for invalid OTP attempts.
	customer, err := GetCustomerByEmail(db, email)
	if err != nil {
		// GetCustomerByEmail already handles "not found" and other DB errors
		return nil, "", "", fmt.Errorf("failed to get customer after OTP verification: %w", err)
	}

		// storedHash, err := redisclient.GetRedisClient().Get(ctx, "otp:"+request.Email).Result()

	// 4. Delete OTP from Redis after successful verification
	if err := redisclient.GetRedisClient().Del(ctx, redisKey).Err(); err != nil {
		// Log this error, but don't fail the login process as verification was successful
		// logger.ErrorLogger.Error("Failed to delete used OTP from Redis for email %s: %w", email, err) // Uncomment if logger
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
	_, err = db.Exec(context.Background(),
		`UPDATE customers SET is_verified_email = TRUE, refresh_token = $1 WHERE id = $2`,
		refreshToken, customer.ID) // Update based on ID after fetching the user
	if err != nil {
		// logger.ErrorLogger.Error("Failed to update customer verification status and refresh token for user ID %s: %w", customer.ID, err) // Uncomment if logger
		// Decide if this should cause login failure or just log a warning.
		// For critical data like refresh tokens, failure might be appropriate.
		return nil, "", "", fmt.Errorf("failed to update customer data after login: %w", err)
	}

	// Update the customer object being returned with the new refresh token and verification status
	customer.IsVerifiedEmail = true
	customer.RefreshToken = &refreshToken // Assign the generated refresh token

	// logger.InfoLogger.Infof("Customer ID %s logged in successfully via OTP", customer.ID) // Uncomment if logger

	// 8. Return customer details, access token, and refresh token
	return customer, accessToken, refreshToken, nil
}