package user_models

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
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
	OTP             *string // Renamed from OTPHash to OTP to reflect potential storage of raw OTP or hash
	FirstName       string
	LastName        string
	IsVerifiedEmail bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
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
		return false, err
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
		// Enhanced error logging with fixed error type handling
		logger.ErrorLogger.Errorf("Token validation error: %v", err)

		log.Printf("Token validation error: %v", err)

		return nil, nil, err
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, nil, errors.New("invalid token claims")
	}

	return token, claims, nil
}

// CreateUser registers a new user and returns JWT & refresh token
func CreateUser(db *pgxpool.Pool, email, password, firstName, lastName string) (*User, error) {
	logger.InfoLogger.Info("CreateUser called on models")

	passwordHash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	userID, err := shared_models.GenerateUUIDv7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUIDv7: %v", err)
	}

	// Insert the user into the database
	query := `INSERT INTO users (id, email, password_hash, first_name, last_name) 
			 VALUES ($1, $2, $3, $4, $5) RETURNING id`
	_, err = db.Exec(context.Background(), query, userID, email, passwordHash, firstName, lastName)
	if err != nil {
		// Check if it's a unique constraint violation
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			return nil, errors.New("email is already registered")
		}
		return nil, err
	}

	user := &User{
		ID:           userID,
		Email:        email,
		PasswordHash: passwordHash,
		FirstName:    firstName,
		LastName:     lastName,
	}

	return user, nil
}

// LoginUser authenticates a user and generates JWT + Refresh Token
func LoginUser(db *pgxpool.Pool, email, password string) (*User, string, string, error) {
	logger.InfoLogger.Info("LoginUser called on models")

	ctx := context.Background()
	user, err := GetUserByEmail(ctx, db, email) // Retrieve user by email
	if err != nil {
		logger.ErrorLogger.Errorf("Login failed for email %s: %v", email, err)
		return nil, "", "", errors.New("invalid credentials")
	}

	valid, err := VerifyPassword(password, user.PasswordHash)
	if err != nil || !valid {
		logger.ErrorLogger.Errorf("Invalid password attempt for user %s", user.ID)
		return nil, "", "", errors.New("invalid credentials")
	}

	currentTokenVersion := user.TokenVersion

	accessToken, err := shared_models.GenerateAccessToken(user.ID, currentTokenVersion, time.Minute*60) // Access Token for 1 hour
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to generate access token for user %s: %v", user.ID, err)
		return nil, "", "", errors.New("failed to generate access token")
	}

	refreshToken, err := shared_models.GenerateRefreshToken(user.ID, currentTokenVersion, time.Hour*24*30) // Stronger Refresh Token for 30 days
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to generate refresh token for user %s: %v", user.ID, err)
		return nil, "", "", errors.New("failed to generate refresh token")
	}

	// Store refresh token in Redis using user ID
	err = redisclient.GetRedisClient(ctx).Set(ctx, shared_utils.USER_REFRESH_TOKEN_PREFIX+user.ID.String(), refreshToken, time.Hour*shared_utils.REFRESH_TOKEN_EXP_HOURS).Err()
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
	// Remove from database (if refresh_token column is still used for old sessions or backup)
	_, err := db.Exec(context.Background(), `UPDATE users SET refresh_token = NULL WHERE id = $1`, userID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to clear refresh token from DB for user %s: %v", userID, err)
		return fmt.Errorf("failed to clear refresh token from DB: %w", err)
	}

	ctx := context.Background()
	// Also delete from Redis
	err = redisclient.GetRedisClient(ctx).Del(ctx, shared_utils.USER_REFRESH_TOKEN_PREFIX+userID.String()).Err()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete refresh token from Redis for user %s: %v", userID, err)
		// Consider if this should be a critical error or just logged
	}
	return nil
}

// GetUserByEmail retrieves a user by email
func GetUserByEmail(ctx context.Context, db *pgxpool.Pool, email string) (*User, error) {
	var user User

	query := `SELECT id, email, first_name, last_name, password_hash, refresh_token, is_verified_email, token_version FROM users WHERE email = $1`

	err := db.QueryRow(context.Background(), query, email).Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.PasswordHash,
		&user.RefreshToken,
		&user.IsVerifiedEmail,
		&user.TokenVersion,
	)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to get user by email: %v", err)
		return nil, err
	}

	return &user, nil
}

// GetUserByID retrieves a user by id
func GetUserByID(db *pgxpool.Pool, id string) (*User, error) {
	var user User
	query := `SELECT id, email, first_name, last_name, password_hash, refresh_token, is_verified_email, token_version FROM users WHERE id = $1`
	err := db.QueryRow(context.Background(), query, id).Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.PasswordHash,
		&user.RefreshToken,
		&user.IsVerifiedEmail,
		&user.TokenVersion,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func IncrementUserTokenVersion(db *pgxpool.Pool, userID uuid.UUID) error {
	query := `UPDATE users SET token_version = token_version + 1 WHERE id = $1`
	_, err := db.Exec(context.Background(), query, userID)
	return err
}

// UpdateUserFields updates specific fields of a user's profile.
// Define allowed fields for updates to prevent SQL injection
func UpdateUserFields(db *pgxpool.Pool, userID uuid.UUID, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil // No updates to perform
	}

	var allowedUpdateFields = map[string]bool{
		"first_name": true,
		"last_name":  true,
		"email":      true, // Email can be updated, but you might want additional verification for email changes
	}

	// Validate field names to prevent SQL injection
	for field := range updates {
		if !allowedUpdateFields[field] {
			return fmt.Errorf("field '%s' is not allowed for updates", field)
		}
	}

	setClauses := []string{}
	args := []interface{}{}
	argCounter := 1

	for field, value := range updates {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", field, argCounter))
		args = append(args, value)
		argCounter++
	}

	query := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d", strings.Join(setClauses, ", "), argCounter)
	args = append(args, userID)

	_, err := db.Exec(context.Background(), query, args...)
	if err != nil {
		return fmt.Errorf("failed to update user fields: %w", err)
	}
	return nil
}

// IsEmailVerified checks if a user's email is verified
func IsEmailVerified(db *pgxpool.Pool, userID uuid.UUID) (bool, error) {
	logger.InfoLogger.Info("IsEmailVerified called on models")

	var isVerified bool
	query := `SELECT is_verified_email FROM users WHERE id = $1`
	err := db.QueryRow(context.Background(), query, userID).Scan(&isVerified)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to check email verification status: %v", err)
		return false, err
	}

	return isVerified, nil
}

func DeleteUser(db *pgxpool.Pool, userID uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := db.Exec(context.Background(), query, userID)
	return err
}
