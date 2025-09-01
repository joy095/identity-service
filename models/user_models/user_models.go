package user_models

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	redisclient "github.com/joy095/identity/config/redis"
	"github.com/joy095/identity/utils/shared_utils"

	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/shared_models"
	"github.com/joy095/identity/utils"

	"golang.org/x/crypto/argon2"
)

// Argon2 Parameters (Strong Security)
const (
	Memory      = 64 * 1024 // 64MB – still strong, far safer for API servers
	Iterations  = 3         // Keep ≈1s hash on commodity hardware          // Number of iterations
	Parallelism = 4         // Number of threads
	SaltLength  = 16        // Salt size (bytes)
	KeyLength   = 64        // Derived key size (bytes)
)

// User Model
type User struct {
	ID              uuid.UUID
	TokenVersion    int
	Email           string
	PasswordHash    string
	RefreshToken    *string
	OTPHash         *string
	FirstName       string
	LastName        string
	IsVerifiedEmail bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Status          string
	Phone           *string
}

// Define allowed fields for updates
var allowedUpdateFields = map[string]bool{
	"first_name": true,
	"last_name":  true,
	"email":      true,
	"phone":      true,
}

// generateSalt generates a secure random salt
func generateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// HashPassword hashes a password using Argon2id
func HashPassword(password string) (string, error) {
	logger.InfoLogger.Info("HashPassword called on models")

	salt, err := generateSalt(SaltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, Iterations, Memory, uint8(Parallelism), KeyLength)

	saltBase64 := base64.RawStdEncoding.EncodeToString(salt)
	hashBase64 := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("%s$%s", saltBase64, hashBase64), nil
}

// VerifyPassword verifies a password against a stored hash
func VerifyPassword(password, storedHash string) (bool, error) {
	logger.InfoLogger.Info("VerifyPassword called on models")

	parts := strings.Split(storedHash, "$")
	if len(parts) != 2 {
		logger.ErrorLogger.Error("invalid stored hash format")
		return false, errors.New("invalid stored hash format")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		logger.ErrorLogger.Error(err)
		return false, err
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		logger.ErrorLogger.Error(err)

		return false, err
	}

	computedHash := argon2.IDKey([]byte(password), salt, Iterations, Memory, uint8(Parallelism), KeyLength)
	if subtle.ConstantTimeCompare(computedHash, expectedHash) == 1 {
		return true, nil
	}
	return false, nil
}

// ComparePasswords compares a provided password with the stored hash for a given email.
func ComparePasswords(db *pgxpool.Pool, password, email string) (bool, error) {
	logger.InfoLogger.Info("ComparePasswords called on models")

	// Fetch the user from the database by email
	user, err := GetUserByEmail(context.Background(), db, email)
	if err != nil {
		logger.ErrorLogger.Errorf("user not found for email %s: %v", email, err)
		// Perform a dummy hash operation to prevent timing attacks
		_, _ = HashPassword(password)
		return false, errors.New("invalid credentials")
	}

	// Verify the provided password against the stored hash
	valid, err := VerifyPassword(password, user.PasswordHash)
	if err != nil {
		logger.ErrorLogger.Errorf("password verification failed for email %s: %v", email, err)
		return false, err
	}

	return valid, nil
}

// ValidateAccessToken with detailed error reporting for debugging
func ValidateAccessToken(tokenString string) (*jwt.Token, jwt.MapClaims, error) {
	logger.InfoLogger.Info("ValidateAccessToken called on models")

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			logger.ErrorLogger.Errorf("unexpected signing method: %v", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		jwtSecret := utils.GetJWTSecret()

		// Return the same secret used for signing
		return jwtSecret, nil
	})

	if err != nil {

		logger.ErrorLogger.Errorf("Token validation error: %v", err)

		return nil, nil, err
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, nil, errors.New("invalid token claims")
	}

	return token, claims, nil
}

// Create user if the user not verified that case will delete the user (after 15 minutes of creation)
func CreateUser(db *pgxpool.Pool, email, password, firstName, lastName string) (*User, error) {
	logger.InfoLogger.Info("CreateUser called on models")

	passwordHash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	// Use a single atomic operation with better conflict handling
	insertQuery := `
		WITH deleted AS (
			DELETE FROM users
			WHERE email = $1
			  AND is_verified_email = FALSE
			  AND created_at < NOW() - INTERVAL '15 minutes'
		)
		INSERT INTO users (email, password_hash, first_name, last_name)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`
	var returnedID uuid.UUID
	err = db.QueryRow(context.Background(), insertQuery, email, passwordHash, firstName, lastName).Scan(&returnedID)
	if err != nil {
		// Check if it's a unique constraint violation
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			// Check if the existing user is verified
			existingUser, checkErr := GetUserByEmail(context.Background(), db, email)
			if checkErr == nil && existingUser.IsVerifiedEmail {
				return nil, errors.New("email is already registered with a verified account")
			}
			return nil, errors.New("email is already in use, please try again later")
		}
		return nil, err
	}

	user := &User{
		ID:           returnedID,
		Email:        email,
		PasswordHash: passwordHash,
		FirstName:    firstName,
		LastName:     lastName,
	}

	return user, nil
}

// LoginUser authenticates a user and generates JWT + Refresh Token (with Redis list support)
func LoginUser(db *pgxpool.Pool, email, password string) (*User, string, string, error) {
	logger.InfoLogger.Info("LoginUser called on models")

	ctx := context.Background()
	user, err := GetUserByEmail(ctx, db, email)
	if err != nil {
		logger.ErrorLogger.Errorf("Login failed for email %s: %v", email, err)
		return nil, "", "", errors.New("invalid credentials")
	}

	valid, err := VerifyPassword(password, user.PasswordHash)
	if err != nil || !valid {
		logger.ErrorLogger.Errorf("Invalid password attempt for user %s", user.ID)
		return nil, "", "", errors.New("invalid credentials")
	}

	// Check if email is verified
	if !user.IsVerifiedEmail {
		logger.ErrorLogger.Errorf("Unverified email login attempt for user %s", user.ID)
		return nil, "", "", errors.New("email not verified")
	}

	currentTokenVersion := user.TokenVersion

	accessToken, err := shared_models.GenerateAccessToken(user.ID, currentTokenVersion, shared_models.ACCESS_TOKEN_EXPIRY)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to generate access token for user %s: %v", user.ID, err)
		return nil, "", "", errors.New("failed to generate access token")
	}

	// Generate Refresh Token
	refreshToken, jti, err := shared_models.GenerateRefreshTokenWithJTI(user.ID, currentTokenVersion, shared_models.REFRESH_TOKEN_EXPIRY)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to generate refresh token for user %s: %v", user.ID, err)
		return nil, "", "", errors.New("failed to generate refresh token")
	}

	// Store refresh token in Redis
	type RefreshTokenEntry struct {
		Token string `json:"token"`
		JTI   string `json:"jti"`
	}
	entry := RefreshTokenEntry{
		Token: refreshToken,
		JTI:   jti,
	}

	entryBytes, err := json.Marshal(entry)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to marshal refresh token entry: %v", err)
		return nil, "", "", fmt.Errorf("failed to marshal refresh token entry: %v", err)
	}

	rdb, err := redisclient.GetRedisClient(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("Redis init failed for user %s: %v", user.ID, err)
		return nil, "", "", fmt.Errorf("failed to connect to Redis: %v", err)
	}
	key := shared_utils.REFRESH_TOKEN_PREFIX + user.ID.String()

	pipe := rdb.Pipeline()
	pipe.LPush(ctx, key, entryBytes)                                      // Add new token
	pipe.LTrim(ctx, key, 0, 9)                                            // Keep only the last 10 tokens
	pipe.Expire(ctx, key, time.Hour*shared_utils.REFRESH_TOKEN_EXP_HOURS) // Reset expiration
	_, err = pipe.Exec(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store refresh token in Redis for user %s: %v", user.ID, err)
		return nil, "", "", fmt.Errorf("failed to store refresh token in Redis: %v", err)
	}

	logger.InfoLogger.Infof("Email verified and tokens generated successfully for user %s", user.ID)

	user.RefreshToken = &refreshToken
	return user, accessToken, refreshToken, nil
}

// LogoutUser removes the refresh token from the database (and Redis if applicable)
func LogoutUser(db *pgxpool.Pool, userID uuid.UUID) error {
	ctx := context.Background()

	// Remove from Redis (best effort - don't fail the entire operation)
	key := shared_utils.REFRESH_TOKEN_PREFIX + userID.String()
	if rdb, err := redisclient.GetRedisClient(ctx); err == nil {
		if delErr := rdb.Del(ctx, key).Err(); delErr != nil {
			logger.ErrorLogger.Errorf("Failed to delete refresh tokens from Redis: %v", delErr)
			// Continue - don't fail the logout
		}
	} else {
		logger.ErrorLogger.Errorf("Failed to connect to Redis during logout: %v", err)
	}

	return nil
}

// CheckUserStatus checks if a user needs to create a new account
func CheckUserStatus(ctx context.Context, db *pgxpool.Pool, email string) (*User, error) {
	query := `
        SELECT email, is_verified_email, created_at
        FROM users
        WHERE email = $1
    `
	rows, err := db.Query(ctx, query, email)
	if err != nil {
		logger.ErrorLogger.Errorf("CheckUserStatus: Failed to query user with email %s due to unexpected DB error: %v", email, err)
		return nil, err // Other database errors
	}
	defer rows.Close()

	// Check if any rows were returned (similar to cursor.rowcount)
	if !rows.Next() {
		logger.InfoLogger.Infof("CheckUserStatus: No user found with email %s. Email is available for new user creation.", email)
		return &User{Email: email, Status: "Not found"}, nil // Return User with "Not found" status
	}

	// Process the single row (similar to Python's for loop, but we expect one row)
	var user User
	err = rows.Scan(
		&user.Email,
		&user.IsVerifiedEmail,
		&user.CreatedAt,
	)
	if err != nil {
		logger.ErrorLogger.Errorf("CheckUserStatus: Failed to scan user data for email %s: %v", email, err)
		return nil, err
	}

	// Ensure no additional rows (shouldn't happen with unique email constraint)
	if rows.Next() {
		logger.ErrorLogger.Errorf("CheckUserStatus: Multiple users found with email %s, expected one.", email)
		return nil, fmt.Errorf("multiple users found for email %s", email)
	}

	// User record was found.
	if user.IsVerifiedEmail {
		user.Status = "Verified"
		return &user, nil // User is verified.
	}

	// User not verified. Check if the 15-minute verification period has expired.
	if user.CreatedAt.UTC().Before(time.Now().UTC().Add(-15 * time.Minute)) {
		logger.InfoLogger.Infof("CheckUserStatus: User with email %s found but verification expired.", email)
		user.Status = "VerificationExpired"
		return &user, nil // Return User with VerificationExpired status
	}

	// User found, not verified, and within 15 mins. (Pending)
	user.Status = "Pending"
	return &user, nil
}

// GetUserByEmail retrieves a user by email
func GetUserByEmail(ctx context.Context, db *pgxpool.Pool, email string) (*User, error) {
	var user User

	query := `SELECT id, email, first_name, last_name, password_hash, is_verified_email, token_version, phone FROM users WHERE email = $1`

	err := db.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.PasswordHash,
		&user.IsVerifiedEmail,
		&user.TokenVersion,
		&user.Phone,
	)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to get user by email: %v", err)
		return nil, err
	}

	return &user, nil
}

// GetUserByID retrieves a user by id
func GetUserByID(ctx context.Context, db *pgxpool.Pool, id uuid.UUID) (*User, error) {
	var user User
	query := `SELECT id, email, first_name, last_name, password_hash, is_verified_email, token_version, phone FROM users WHERE id = $1`
	err := db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.PasswordHash,
		&user.IsVerifiedEmail,
		&user.TokenVersion,
		&user.Phone,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func IncrementUserTokenVersion(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID) error {
	query := `UPDATE users SET token_version = token_version + 1 WHERE id = $1`
	_, err := db.Exec(ctx, query, userID)
	return err
}

// Define allowed fields for updates to prevent SQL injection
func UpdateUserFields(db *pgxpool.Pool, userID uuid.UUID, updates map[string]interface{}) error {

	// Validate that only allowed fields are being updated
	for field := range updates {
		if !allowedUpdateFields[field] {
			return fmt.Errorf("field '%s' is not allowed for update", field)
		}
	}

	if len(updates) == 0 {
		return nil // No updates to perform
	}

	// Use COALESCE to update only provided fields
	query := `
		UPDATE users 
		SET 
			first_name = COALESCE($2, first_name),
			last_name  = COALESCE($3, last_name),
			email      = COALESCE($4, email),
			phone      = COALESCE($5, phone),
			updated_at = NOW()
		WHERE id = $1
	`

	var firstName, lastName, email, phone interface{}
	if val, ok := updates["first_name"]; ok {
		firstName = val
	}
	if val, ok := updates["last_name"]; ok {
		lastName = val
	}
	if val, ok := updates["email"]; ok {
		email = val
	}
	if val, ok := updates["phone"]; ok {
		phone = val
	}

	args := []interface{}{userID, firstName, lastName, email, phone}

	_, err := db.Exec(context.Background(), query, args...)
	if err != nil {
		return fmt.Errorf("failed to update user fields: %w", err)
	}
	return nil
}

// IsEmailVerified checks if a user's email is verified
func IsEmailVerified(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID) (bool, error) {
	logger.InfoLogger.Info("IsEmailVerified called on models")

	var isVerified bool
	query := `SELECT is_verified_email FROM users WHERE id = $1`
	err := db.QueryRow(ctx, query, userID).Scan(&isVerified)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to check email verification status: %v", err)
		return false, err
	}

	return isVerified, nil
}

func DeleteUser(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID) error {
	// Begin transaction
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) // Will be no-op if commit succeeds

	// Delete from Redis first
	key := shared_utils.REFRESH_TOKEN_PREFIX + userID.String()
	if rdb, err := redisclient.GetRedisClient(ctx); err != nil {
		logger.ErrorLogger.Errorf("Failed to init Redis client: %v", err)
		// continue with user deletion even if Redis fails
	} else if delErr := rdb.Del(ctx, key).Err(); delErr != nil {
		logger.ErrorLogger.Errorf("Failed to delete refresh tokens from Redis: %v", delErr)
		// continue with user deletion even if Redis fails
	}

	// Delete user from database
	query := `DELETE FROM users WHERE id = $1`
	result, err := tx.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
