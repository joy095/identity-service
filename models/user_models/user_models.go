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

var ctx = context.Background()

// Argon2 Parameters (Strong Security)
const (
	Memory      = 64 * 1024 // 64MB – still strong, far safer for API servers
	Iterations  = 3         // Keep ≈1s hash on commodity hardware          // Number of iterations
	Parallelism = 4         // Number of threads
	SaltLength  = 16        // Salt size (bytes)
	KeyLength   = 64        // Derived key size (bytes)
)

// User Model
type User struct {
	ID              uuid.UUID
	Username        string
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
	if subtle.ConstantTimeCompare(computedHash, expectedHash) == 1 {
		return true, nil
	}
	return false, nil
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

	user, err := GetUserByUsername(db, username) // This function should retrieve the User struct, including TokenVersion
	if err != nil {
		// It's good practice to log the specific error for debugging but return a generic one for security
		logger.ErrorLogger.Errorf("Login failed for username %s: %v", username, err)
		return nil, "", "", errors.New("invalid credentials") // Avoid "user not found" for security
	}

	valid, err := VerifyPassword(password, user.PasswordHash) // Assuming PasswordHash is the correct field
	if err != nil || !valid {
		logger.ErrorLogger.Errorf("Invalid password attempt for user %s", user.ID)
		return nil, "", "", errors.New("invalid credentials")
	}

	// --- Pass the user's current TokenVersion to token generation ---
	// user.TokenVersion should be populated by GetUserByUsername
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

	// --- Important: Re-evaluate refresh token storage in DB ---

	err = redisclient.GetRedisClient().Set(ctx, shared_utils.USER_REFRESH_TOKEN_PREFIX+user.Username, refreshToken, time.Hour*shared_utils.REFRESH_TOKEN_EXP_HOURS).Err()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store refresh token in Redis for user %s: %v", user.ID, err)
		return nil, "", "", fmt.Errorf("failed to store refresh token in Redis: %v", err)
	}

	logger.InfoLogger.Infof("Email verified and tokens generated successfully for user %s", user.ID)

	// Set the generated refresh token on the user object before returning
	user.RefreshToken = &refreshToken // Ensure User struct can hold a pointer to string if that's its type
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

	query := `SELECT id, username, email, first_name, last_name, password_hash, refresh_token, is_verified_email, token_version FROM users WHERE username = $1`

	err := db.QueryRow(context.Background(), query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.PasswordHash,
		&user.RefreshToken,
		&user.IsVerifiedEmail,
		&user.TokenVersion,
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
	query := `SELECT id, username, email, first_name, last_name, password_hash, refresh_token, is_verified_email, token_version FROM users WHERE id = $1`
	err := db.QueryRow(context.Background(), query, id).Scan(
		&user.ID,
		&user.Username,
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

func UpdatePasswordAndIncrementVersion(db *pgxpool.Pool, userID uuid.UUID, newPassword string) error {

	tx, err := db.Begin(context.Background())

	if err != nil {
		return err
	}

	defer tx.Rollback(context.Background())

	query := `UPDATE users SET password_hash = $1, token_version = token_version + 1 WHERE id = $2`

	_, err = tx.
		Exec(context.Background(), query, newPassword, userID)

	if err != nil {
		return err
	}

	return tx.Commit(context.Background())

}

// UpdateUserFields updates specific fields of a user's profile.
// Define allowed fields for updates to prevent SQL injection
func UpdateUserFields(db *pgxpool.Pool, userID uuid.UUID, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil // No updates to perform
	}

	var allowedUpdateFields = map[string]bool{
		"username":   true,
		"first_name": true,
		"last_name":  true,
		"email":      true,
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
