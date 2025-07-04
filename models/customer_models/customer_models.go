package customer_models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool" // pgxpool for database connections
	redisclient "github.com/joy095/identity/config/redis"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/shared_models"
	"github.com/joy095/identity/utils"
	"github.com/joy095/identity/utils/shared_utils"
	"github.com/redis/go-redis/v9"
)

// Customer Model
type Customer struct {
	ID              uuid.UUID
	Email           string
	FirstName       *string // Changed to pointer to string
	LastName        *string // Changed to pointer to string
	IsVerifiedEmail bool
	TokenVersion    int
}

const refreshTokenExpiry = time.Hour * 24 * 30 // 30 days

// RefreshTokenEntry represents a single refresh token with its associated device information
type RefreshTokenEntry struct {
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	Device    string    `json:"device,omitempty"` // e.g., "web", "mobile_ios", "mobile_android"
}

// --- Database Operations for Customer ---

// CreateCustomer function (This was missing, re-added)
func CreateCustomer(ctx context.Context, db *pgxpool.Pool, email string) (*Customer, error) {
	logger.InfoLogger.Info("CreateCustomer called on models")

	userID, err := shared_models.GenerateUUIDv7() // Assuming GenerateUUIDv7 is defined elsewhere
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %w", err)
	}

	query := `INSERT INTO customers (id, email)
              VALUES ($1, $2) RETURNING id, email, first_name, last_name, is_verified_email, token_version`

	// Initialize pointers to nil for nullable fields when creating a new user
	var firstName *string
	var lastName *string

	customer := &Customer{}
	err = db.QueryRow(ctx, query, userID, email).Scan(
		&customer.ID,
		&customer.Email,
		&firstName,
		&lastName,
		&customer.IsVerifiedEmail,
		&customer.TokenVersion,
	)
	if err != nil {
		return nil, err
	}
	customer.FirstName = firstName
	customer.LastName = lastName

	return customer, nil
}

func IsUsernameAvailable(db *pgxpool.Pool, email string) (bool, error) {
	logger.InfoLogger.Info("IsUsernameAvailable called on models")

	query := `SELECT COUNT(*) FROM customers WHERE email = $1`

	var count int
	err := db.QueryRow(context.Background(), query, email).Scan(&count)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to check email availability: %v", err)
		return false, fmt.Errorf("failed to check email availability: %v", err)
	}

	return count == 0, nil
}

// GetCustomerByEmail function
func GetCustomerByEmail(db *pgxpool.Pool, email string) (*Customer, error) {
	var customer Customer
	// Use pointers for FirstName and LastName to handle NULLs from the database
	var firstName, lastName *string

	query := `SELECT id, email, first_name, last_name, is_verified_email, token_version FROM customers WHERE email = $1`
	err := db.QueryRow(context.Background(), query, email).Scan(
		&customer.ID, &customer.Email, &firstName, &lastName, &customer.IsVerifiedEmail, &customer.TokenVersion,
	)
	if err != nil {
		return nil, err // Return error directly, including pgx.ErrNoRows if not found
	}
	customer.FirstName = firstName // Assign the potentially nil pointer
	customer.LastName = lastName   // Assign the potentially nil pointer
	return &customer, nil
}

// GetCustomerByID retrieves a customer record from the database by their ID.
// It also fetches the token_version which is essential for JWT invalidation.
func GetCustomerByID(db *pgxpool.Pool, customerID uuid.UUID) (*Customer, error) {
	var customer Customer
	// Use pointers for FirstName and LastName to handle NULLs from the database
	var firstName, lastName *string

	// Ensure the query selects all necessary fields, including token_version
	query := `SELECT id, email, first_name, last_name, is_verified_email, token_version FROM customers WHERE id = $1`

	err := db.QueryRow(context.Background(), query, customerID).Scan(
		&customer.ID,
		&customer.Email,
		&firstName,
		&lastName,
		&customer.IsVerifiedEmail,
		&customer.TokenVersion, // Scan the token_version here
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			// Return a specific error if no customer is found
			return nil, fmt.Errorf("customer with ID %s not found", customerID.String())
		}
		// Return general database error for other issues
		return nil, fmt.Errorf("database error fetching customer by ID %s: %w", customerID.String(), err)
	}

	// Assign the potentially nil pointers to the struct fields
	customer.FirstName = firstName
	customer.LastName = lastName

	return &customer, nil
}

// --- Refresh Token Management in Redis ---

// storeRefreshTokenInRedis stores a new refresh token for a user and device
func storeRefreshTokenInRedis(ctx context.Context, userID uuid.UUID, refreshToken string, device string) error {
	redisKey := fmt.Sprintf("refresh_tokens:%s", userID.String())

	existingTokensJSON, err := redisclient.GetRedisClient().Get(ctx, redisKey).Result()
	var tokenEntries []RefreshTokenEntry
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("failed to get existing refresh tokens from Redis: %w", err)
	}

	if existingTokensJSON != "" {
		if err := json.Unmarshal([]byte(existingTokensJSON), &tokenEntries); err != nil {
			return fmt.Errorf("failed to unmarshal existing refresh tokens: %w", err)
		}
	}

	newTokenEntry := RefreshTokenEntry{
		Token:     refreshToken,
		CreatedAt: time.Now(),
		Device:    device,
	}
	tokenEntries = append(tokenEntries, newTokenEntry)

	updatedTokensJSON, err := json.Marshal(tokenEntries)
	if err != nil {
		return fmt.Errorf("failed to marshal updated refresh tokens: %w", err)
	}

	if err := redisclient.GetRedisClient().Set(ctx, redisKey, updatedTokensJSON, refreshTokenExpiry).Err(); err != nil {
		return fmt.Errorf("failed to store refresh token in Redis: %w", err)
	}
	logger.InfoLogger.Infof("Refresh token stored in Redis for user %s, device %s", userID, device)
	return nil
}

// updateRefreshTokenInRedis updates an existing refresh token for a user and device
// This function can be used if you want to strictly manage one refresh token per device
// and replace it on each new login from that device.
func updateRefreshTokenInRedis(ctx context.Context, userID uuid.UUID, oldRefreshToken, newRefreshToken, device string) error {
	redisKey := fmt.Sprintf("refresh_tokens:%s", userID.String())

	existingTokensJSON, err := redisclient.GetRedisClient().Get(ctx, redisKey).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("failed to get existing refresh tokens from Redis: %w", err)
	}

	var tokenEntries []RefreshTokenEntry
	if existingTokensJSON != "" {
		if err := json.Unmarshal([]byte(existingTokensJSON), &tokenEntries); err != nil {
			return fmt.Errorf("failed to unmarshal existing refresh tokens: %w", err)
		}
	}

	found := false
	for i, entry := range tokenEntries {
		if entry.Token == oldRefreshToken && entry.Device == device {
			tokenEntries[i].Token = newRefreshToken
			tokenEntries[i].CreatedAt = time.Now()
			found = true
			break
		}
	}

	if !found {
		newTokenEntry := RefreshTokenEntry{
			Token:     newRefreshToken,
			CreatedAt: time.Now(),
			Device:    device,
		}
		tokenEntries = append(tokenEntries, newTokenEntry)
	}

	updatedTokensJSON, err := json.Marshal(tokenEntries)
	if err != nil {
		return fmt.Errorf("failed to marshal updated refresh tokens: %w", err)
	}

	if err := redisclient.GetRedisClient().Set(ctx, redisKey, updatedTokensJSON, refreshTokenExpiry).Err(); err != nil {
		return fmt.Errorf("failed to update refresh token in Redis: %w", err)
	}
	logger.InfoLogger.Infof("Refresh token updated in Redis for user %s, device %s", userID, device)
	return nil
}

// ValidateRefreshTokenInRedis checks if a given refresh token is valid for a user
func ValidateRefreshTokenInRedis(ctx context.Context, userID uuid.UUID, refreshToken string) (bool, error) {
	redisKey := fmt.Sprintf("refresh_tokens:%s", userID.String())
	existingTokensJSON, err := redisclient.GetRedisClient().Get(ctx, redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil // No refresh tokens found for this user
		}
		return false, fmt.Errorf("failed to get refresh tokens from Redis: %w", err)
	}

	var tokenEntries []RefreshTokenEntry
	if err := json.Unmarshal([]byte(existingTokensJSON), &tokenEntries); err != nil {
		return false, fmt.Errorf("failed to unmarshal existing refresh tokens: %w", err)
	}

	for _, entry := range tokenEntries {
		if entry.Token == refreshToken {
			// Token exists and Redis hasn't expired it yet
			return true, nil
		}
	}
	return false, nil // Token not found or expired
}

// LoginCustomer authenticates a customer using OTP and generates tokens
func LoginCustomer(ctx context.Context, db *pgxpool.Pool, email string, otp string, device string) (*Customer, string, string, error) {
	logger.InfoLogger.Info("LoginCustomer (OTP verification) called on models")

	redisKeyOTP := shared_utils.CUSTOMER_OTP_PREFIX + strings.ToLower(strings.TrimSpace(email))
	storedHash, err := redisclient.GetRedisClient().Get(ctx, redisKeyOTP).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			logger.ErrorLogger.Info(fmt.Sprintf("OTP expired or not found for %s", email))
			return nil, "", "", errors.New("OTP expired or not found")
		}
		logger.ErrorLogger.Errorf("Failed to retrieve OTP from Redis for %s: %v", email, err)
		return nil, "", "", fmt.Errorf("internal server error during OTP verification: %w", err)
	}

	providedHash := utils.HashOTP(strings.TrimSpace(otp))
	if providedHash != storedHash {
		logger.ErrorLogger.Info(fmt.Sprintf("Incorrect OTP for %s", email))
		return nil, "", "", errors.New("incorrect OTP")
	}

	customer, err := GetCustomerByEmail(db, email) // This function MUST retrieve the Customer struct including TokenVersion
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get customer by email %s after OTP verification: %v", email, err)
		return nil, "", "", fmt.Errorf("customer not found or database error: %w", err) // More generic error
	}

	if err := redisclient.GetRedisClient().Del(ctx, redisKeyOTP).Err(); err != nil {
		logger.ErrorLogger.Warnf("Failed to delete OTP from Redis for email %s: %w", email, err)
		// Don't return error here, as OTP verification already succeeded
	}

	// --- INTEGRATE TOKEN_VERSION HERE ---
	// Get the customer's current token_version from the fetched customer object.
	currentTokenVersion := customer.TokenVersion

	accessToken, err := shared_models.GenerateAccessToken(customer.ID, currentTokenVersion, time.Minute*60)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to generate access token for customer %s: %w", customer.ID, err)
		return nil, "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := shared_models.GenerateRefreshToken(customer.ID, currentTokenVersion, refreshTokenExpiry)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to generate refresh token for customer %s: %w", customer.ID, err)
		return nil, "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	// --- END TOKEN_VERSION INTEGRATION ---

	// Store refresh token in Redis (assuming storeRefreshTokenInRedis manages unique keys per device/session)
	err = storeRefreshTokenInRedis(ctx, customer.ID, refreshToken, device) // Ensure this function handles the unique key based on device/JTI
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store refresh token in Redis for customer %s and device %s: %w", customer.ID, device, err)
		return nil, "", "", fmt.Errorf("failed to store refresh token in Redis: %w", err)
	}

	tx, err := db.Begin(context.Background())
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to begin transaction for customer %s login: %w", customer.ID, err)
		return nil, "", "", fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(context.Background()) // Rollback on error

	// Update is_verified_email status (if not already true)
	if !customer.IsVerifiedEmail {
		_, err = tx.Exec(context.Background(),
			`UPDATE customers SET is_verified_email = TRUE WHERE id = $1`,
			customer.ID)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to update customer verification status for %s: %w", customer.ID, err)
			return nil, "", "", fmt.Errorf("failed to update customer verification status: %w", err)
		}
		customer.IsVerifiedEmail = true // Update in-memory struct
	}

	if err = tx.Commit(context.Background()); err != nil {
		logger.ErrorLogger.Errorf("Failed to commit transaction for customer %s login: %w", customer.ID, err)
		return nil, "", "", fmt.Errorf("failed to commit transaction: %w", err)
	}

	logger.InfoLogger.Infof("Customer ID %s logged in successfully via OTP", customer.ID)

	return customer, accessToken, refreshToken, nil
}
