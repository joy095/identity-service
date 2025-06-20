package shared_utils

import (
	"context"
	"errors"
	"fmt"
	"time"

	redisclient "github.com/joy095/identity/config/redis"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/utils"
)

var ctx = context.Background()

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

	CUSTOMER_OTP_PREFIX           = "customer_otp:"
	CUSTOMER_REFRESH_TOKEN_PREFIX = "customer_refresh_token:"

	USER_REFRESH_TOKEN_PREFIX = "user_refresh_token:"
)

// ErrOTPNotFound is returned when an OTP is not found or expired.
var ErrOTPNotFound = errors.New("otp not found or expired")

// --- OTP Storage and Retrieval Functions ---

// StoreOTP hash in Redis with expiration
func StoreOTP(key string, otp string) error {
	hashedOTP := utils.HashOTP(otp)
	err := redisclient.GetRedisClient().Set(ctx, key, hashedOTP, 10*time.Minute).Err()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store OTP with key %s: %v", key, err)
		return fmt.Errorf("failed to store OTP: %w", err)
	}
	return nil
}

// RetrieveOTP hash from Redis
func RetrieveOTP(key string) (string, error) {
	storedHash, err := redisclient.GetRedisClient().Get(ctx, key).Result()
	if err != nil {
		if err.Error() == "redis: nil" {
			return "", ErrOTPNotFound
		}
		logger.ErrorLogger.Errorf("Failed to retrieve OTP for key %s: %v", key, err)
		return "", fmt.Errorf("failed to retrieve OTP: %w", err)
	}
	return storedHash, nil
}

// ClearOTP from Redis
func ClearOTP(key string) error {
	err := redisclient.GetRedisClient().Del(ctx, key).Err()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to clear OTP for key %s: %v", key, err)
		return fmt.Errorf("failed to clear OTP: %w", err)
	}
	return nil
}
