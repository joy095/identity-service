package shared_utils

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	redisclient "github.com/joy095/identity/config/redis"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/utils"
	"github.com/redis/go-redis/v9"
)

// Define durations for OTPs and tokens
const (
	OTP_EXPIRATION_MINUTES         = 10
	EMAIL_CHANGE_CONFIRM_EXP_HOURS = 24      // Confirmation link valid for 24 hours
	NEW_EMAIL_OTP_EXP_MINUTES      = 10      // OTP for new email valid for 10 minutes
	REFRESH_TOKEN_EXP_HOURS        = 30 * 24 // Refresh token valid for 30 days
)

const (
	FORGOT_PASSWORD_OTP_PREFIX    = "forgot_password_otp:"
	EMAIL_VERIFICATION_OTP_PREFIX = "email_verification_otp:"
	EMAIL_CHANGE_NEW_OTP_PREFIX   = "email_change_new_otp:" // For verifying the new email
	PASSWORD_RESET_OTP_PREFIX     = "password_reset_otp:"

	USER_REFRESH_TOKEN_PREFIX = "user_refresh_token:"
)

// ErrOTPNotFound is returned when an OTP is not found or expired.
var ErrOTPNotFound = errors.New("otp not found or expired")

// --- OTP Storage and Retrieval Functions ---

// StoreOTP hash in Redis with expiration
func StoreOTP(ctx context.Context, key string, otp string) error {
	hashedOTP := utils.HashOTP(otp)
	err := redisclient.GetRedisClient(ctx).Set(ctx, key, hashedOTP, OTP_EXPIRATION_MINUTES*time.Minute).Err()

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store OTP with key %s: %v", key, err)
		return fmt.Errorf("failed to store OTP: %w", err)
	}
	return nil
}

// RetrieveOTP hash from Redis
func RetrieveOTP(ctx context.Context, key string) (string, error) {
	storedHash, err := redisclient.GetRedisClient(ctx).Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", ErrOTPNotFound
		}
		logger.ErrorLogger.Errorf("Failed to retrieve OTP for key %s: %v", key, err)
		return "", fmt.Errorf("failed to retrieve OTP: %w", err)
	}
	return storedHash, nil
}

// ClearOTP from Redis
func ClearOTP(ctx context.Context, key string) error {
	err := redisclient.GetRedisClient(ctx).Del(ctx, key).Err()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to clear OTP for key %s: %v", key, err)
		return fmt.Errorf("failed to clear OTP: %w", err)
	}
	return nil
}

const charset = "0123456789-abcdefghijklmnopqrstuvwxyz"

func GenerateTinyID(length int) (string, error) {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to generate random number: %v", err)
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}
		result[i] = charset[num.Int64()]
	}
	return string(result), nil
}
