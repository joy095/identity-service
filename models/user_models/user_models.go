package user_models

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/shared_models"
	"github.com/joy095/identity/utils"

	"golang.org/x/crypto/argon2"
)

// Argon2 Parameters (Strong Security)
const (
	Memory      = 256 * 1024 // 256MB
	Iterations  = 6          // Number of iterations
	Parallelism = 4          // Number of threads
	SaltLength  = 16         // Salt size (bytes)
	KeyLength   = 64         // Derived key size (bytes)
)

// User Model
type User struct {
	ID              uuid.UUID
	Username        string
	Email           string
	PasswordHash    string
	RefreshToken    *string
	OTP             *string // Renamed from OTPHash to OTP to reflect potential storage of raw OTP or hash
	FirstName       string
	LastName        string
	IsVerifiedEmail bool
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
	logger.InfoLogger.Info("HashPassword called  on models")

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

	return string(computedHash) == string(expectedHash), nil
}

func ComparePasswords(db *pgxpool.Pool, password, username string) (bool, error) {
	logger.InfoLogger.Info("ComparePasswords called on models")

	// Fetch the user from the database
	user, err := GetUserByUsername(db, username)
	if err != nil {
		logger.ErrorLogger.Errorf("user not found: %v", err)
		return false, err
	}

	// Verify the provided password against the stored hash
	valid, err := VerifyPassword(password, user.PasswordHash)
	if err != nil {
		logger.ErrorLogger.Errorf("password verification failed: %v", err)
		return false, err
	}

	return valid, nil
}

// GenerateAccessToken creates a JWT token with base64-encoded secret compatibility
func GenerateAccessToken(userID uuid.UUID, duration time.Duration) (string, error) {
	now := time.Now()

	// Use MapClaims for maximum compatibility
	claims := jwt.MapClaims{
		"sub":     userID.String(),
		"user_id": userID.String(),
		"iat":     now.Unix(),
		"exp":     now.Add(duration).Unix(),
		"nbf":     now.Unix(),
		"jti":     uuid.NewString(),
		"iss":     "identity-service",
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	jwtSecret := utils.GetJWTSecret()

	// Sign the token with the secret key
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to sign token: %v", err)

		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return tokenString, nil
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

		// if strings.Contains(err.Error(), "token is malformed") {
		// 	return nil, nil, fmt.Errorf("token is malformed: %v", err)
		// } else if strings.Contains(err.Error(), "token is expired") {
		// 	return nil, nil, fmt.Errorf("token is expired: %v", err)
		// } else if strings.Contains(err.Error(), "token not valid yet") {
		// 	return nil, nil, fmt.Errorf("token not valid yet: %v", err)
		// } else if strings.Contains(err.Error(), "signature is invalid") {
		// 	return nil, nil, fmt.Errorf("signature validation failed: %v", err)
		// }

		return nil, nil, err
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, nil, errors.New("invalid token claims")
	}

	return token, claims, nil
}

// IsUsernameAvailable checks if a username is available in the database.
func IsUsernameAvailable(db *pgxpool.Pool, username string) (bool, error) {
	logger.InfoLogger.Info("IsUsernameAvailable called on models")

	query := `SELECT COUNT(*) FROM users WHERE username = $1`

	var count int
	err := db.QueryRow(context.Background(), query, username).Scan(&count)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to check username availability: %v", err)
		return false, fmt.Errorf("failed to check username availability: %v", err)
	}

	return count == 0, nil

}

// CreateUser registers a new user and returns JWT & refresh token
func CreateUser(db *pgxpool.Pool, username, email, password, firstName, lastName string) (*User, string, string, error) {
	logger.InfoLogger.Info("CreateUser called on models")

	passwordHash, err := HashPassword(password)
	if err != nil {
		return nil, "", "", err
	}

	userID, err := shared_models.GenerateUUIDv7()
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate UUIDv7: %v", err)
	}

	query := `INSERT INTO users (id, username, email, password_hash, first_name, last_name) 
			  VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`
	_, err = db.Exec(context.Background(), query, userID, username, email, passwordHash, firstName, lastName)
	if err != nil {
		return nil, "", "", err
	}

	user := &User{
		ID:           userID,
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
		FirstName:    firstName,
		LastName:     lastName,
	}

	return user, "", "", nil

}

// LoginUser authenticates a user and generates JWT + Refresh Token
func LoginUser(db *pgxpool.Pool, username, password string) (*User, string, string, error) {
	logger.InfoLogger.Info("LoginUser called on models")

	user, err := GetUserByUsername(db, username)
	if err != nil {
		return nil, "", "", err
	}

	valid, err := VerifyPassword(password, user.PasswordHash)
	if err != nil || !valid {
		return nil, "", "", errors.New("invalid credentials")
	}

	accessToken, err := GenerateAccessToken(user.ID, time.Minute*60) // Access Token for 1 hour
	if err != nil {
		return nil, "", "", err
	}

	refreshToken, err := shared_models.GenerateRefreshToken(user.ID, time.Hour*24*30) // Stronger Refresh Token for 30 days
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

// LogoutUser removes the refresh token from the database
func LogoutUser(db *pgxpool.Pool, userID uuid.UUID) error {
	_, err := db.Exec(context.Background(), `UPDATE users SET refresh_token = NULL WHERE id = $1`, userID)
	return err
}

// GetUserByUsername retrieves a user by username
func GetUserByUsername(db *pgxpool.Pool, username string) (*User, error) {
	var user User

	query := `SELECT id, username, email, first_name, last_name, password_hash, refresh_token, is_verified_email FROM users WHERE username = $1`

	err := db.QueryRow(context.Background(), query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.PasswordHash,
		&user.RefreshToken,
		&user.IsVerifiedEmail,
	)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to get user by username: %v", err)
		return nil, err
	}

	return &user, nil
}

// GetUserByID retrieves a user by id
func GetUserByID(db *pgxpool.Pool, id string) (*User, error) {
	var user User
	query := `SELECT id, username, email, first_name, last_name, password_hash, refresh_token, is_verified_email FROM users WHERE id = $1`
	err := db.QueryRow(context.Background(), query, id).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.PasswordHash,
		&user.RefreshToken,
		&user.IsVerifiedEmail,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateUserFields updates specific fields of a user's profile.
// Define allowed fields for updates to prevent SQL injection
var allowedUpdateFields = map[string]bool{
	"username":   true,
	"first_name": true,
	"last_name":  true,
	"email":      true,
}

func UpdateUserFields(db *pgxpool.Pool, userID uuid.UUID, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil // No updates to perform
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
