package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	redisclient "github.com/joy095/identity/config/redis"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/shared_models"
	"github.com/joy095/identity/models/user_models"
	"github.com/joy095/identity/utils"
	"github.com/joy095/identity/utils/shared_utils"
	"github.com/redis/go-redis/v9"
	gomail "gopkg.in/gomail.v2" // Import gomail
)

const (
	ForgotPasswordTemplate    = "templates/email/forgot_password_otp.html"
	EmailVerificationTemplate = "templates/email/email_verification_otp.html"
	VerifyNewEmailOTPTemplate = "templates/email/verify_new_email_otp.html"
)

// The `parsedTemplates` variable will be populated by an external call.
var parsedTemplates *template.Template

// InitTemplates initializes the email templates using the provided embedded file system.
// This function should be called ONCE during application startup (from main.go).
func InitTemplates(fs embed.FS) {
	var err error

	templatePattern := "templates/email/*.html" // If templates are directly in email folder

	// `ParseFS` can take a variadic list of file patterns
	parsedTemplates, err = template.ParseFS(fs, templatePattern)
	if err != nil {
		log.Fatalf("Mail Package: failed to parse email templates: %v", err)
	}

	log.Println("Mail Package: Templates loaded successfully.")
}

// ErrOTPNotFound is returned when an OTP is not found or expired.
var ErrOTPNotFound = errors.New("otp not found or expired")

// --- Helper function to send email using gomail ---
func sendEmail(toEmail, subject, templateFullPath string, data interface{}) error {
	if parsedTemplates == nil {
		return fmt.Errorf("mail package: templates not initialised - call InitTemplates() at startup")
	}
	mailer := gomail.NewMessage()
	mailer.SetHeader("From", os.Getenv("FROM_EMAIL"))
	mailer.SetHeader("To", toEmail)
	mailer.SetHeader("Subject", subject)

	// Extract just the base name from the full path constant
	// This is the common fix when ParseFS names templates by their file name.
	templateName := templateFullPath[strings.LastIndex(templateFullPath, "/")+1:]
	if templateName == "" { // Handle case where path is just a filename or root
		templateName = templateFullPath
	}

	// Use the pre-parsed templates.
	t := parsedTemplates.Lookup(templateName)
	if t == nil {
		logger.ErrorLogger.Errorf("Mail Package: template '%s' (looked up as '%s') not found in parsedTemplates", templateFullPath, templateName)
		return fmt.Errorf("mail package: email template %s not found", templateFullPath)
	}

	var body bytes.Buffer
	if err := t.Execute(&body, data); err != nil {
		logger.ErrorLogger.Errorf("Failed to execute email template %s: %v", templateFullPath, err)
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	mailer.SetBody("text/html", body.String())

	// ... (rest of your sendEmail function remains the same)
	port, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid SMTP port: %v", err)
		return fmt.Errorf("invalid SMTP port: %w", err)
	}

	smtpHost := os.Getenv("SMTP_HOST")
	smtpUsername := os.Getenv("SMTP_USERNAME")
	smtpPassword := os.Getenv("SMTP_PASSWORD")

	dialer := gomail.NewDialer(smtpHost, port, smtpUsername, smtpPassword)

	dialer.TLSConfig = &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         smtpHost,
	}

	logger.InfoLogger.Printf("Attempting to connect to SMTP server: %s:%d", smtpHost, port)

	if err := dialer.DialAndSend(mailer); err != nil {
		logger.ErrorLogger.Errorf("Failed to send email to %s: %v", toEmail, err)
		return fmt.Errorf("failed to send email: %w", err)
	}

	logger.InfoLogger.Printf("Successfully connected to SMTP server and sent email to %s", toEmail)
	return nil
}

// --- Email Sending Functions (using the new sendEmail helper) ---

// SendForgotPasswordOTP sends an OTP for password reset
func SendForgotPasswordOTP(email, firstName, lastName, otp string) error {
	logger.InfoLogger.Infof("Sending Forgot Password OTP to %s", email)
	data := struct {
		FirstName string
		LastName  string
		OTP       string
		Year      int
	}{
		FirstName: firstName,
		LastName:  lastName,
		OTP:       otp,
		Year:      time.Now().Year(),
	}
	return sendEmail(email, "Password Reset OTP", ForgotPasswordTemplate, data)
}

// SendVerificationOTP sends an OTP for email verification (initial registration)
func SendVerificationOTP(email, firstName, lastName, otp string) error {
	logger.InfoLogger.Infof("Sending Email Verification OTP to %s", email)
	data := struct {
		FirstName string
		LastName  string
		OTP       string
		Year      int
	}{
		FirstName: firstName,
		LastName:  lastName,
		OTP:       otp,
		Year:      time.Now().Year(),
	}
	return sendEmail(email, "Verify Your Email Address", EmailVerificationTemplate, data)
}

// SendEmailChangeNewOTP sends an OTP to the new email for verification.
func SendEmailChangeNewOTP(newEmail, firstName, lastName, otp string) error {
	logger.InfoLogger.Infof("Sending new email verification OTP to %s", newEmail)
	data := struct {
		FirstName string
		LastName  string
		NewEmail  string
		OTP       string
		Year      int
	}{
		FirstName: firstName,
		LastName:  lastName,
		NewEmail:  newEmail,
		OTP:       otp,
		Year:      time.Now().Year(),
	}
	return sendEmail(newEmail, "Verify Your New Email Address", VerifyNewEmailOTPTemplate, data)
}

// StoreEmailChangeNewOTP stores the OTP in Redis for the new email address verification.
func StoreEmailChangeNewOTP(ctx context.Context, userID, newEmail, otpHash string) error {
	logger.InfoLogger.Infof("Storing new email change OTP for user %s, new email %s", userID, newEmail)

	// Get Redis client
	rdb, err := redisclient.GetRedisClient(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to init Redis client: %v", err)
		return fmt.Errorf("failed to init redis client: %w", err)
	}

	key := shared_utils.EMAIL_CHANGE_NEW_OTP_PREFIX + userID
	// Store newEmail along with the OTP hash
	value := fmt.Sprintf("%s:%s", otpHash, newEmail)

	err = rdb.Set(ctx, key, value, time.Minute*time.Duration(shared_utils.NEW_EMAIL_OTP_EXP_MINUTES)).Err()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store new email change OTP for user %s: %v", userID, err)
		return fmt.Errorf("failed to store new email change OTP: %w", err)
	}

	return nil
}

// RetrieveEmailChangeNewOTP retrieves the OTP hash and new email for verification.
// Returns (otpHash, newEmail, error)
func RetrieveEmailChangeNewOTP(ctx context.Context, userID string) (string, string, error) {
	logger.InfoLogger.Infof("Retrieving new email change OTP for user %s", userID)

	// Get Redis client
	rdb, err := redisclient.GetRedisClient(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to init Redis client: %v", err)
		return "", "", fmt.Errorf("failed to init redis client: %w", err)
	}

	key := shared_utils.EMAIL_CHANGE_NEW_OTP_PREFIX + userID

	value, err := rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) { // safer than checking err.Error() == "redis: nil"
			return "", "", ErrOTPNotFound
		}
		logger.ErrorLogger.Errorf("Failed to retrieve new email change OTP for user %s: %v", userID, err)
		return "", "", fmt.Errorf("failed to retrieve new email change OTP: %w", err)
	}

	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		logger.ErrorLogger.Errorf("Invalid format for stored new email change OTP for user %s: %s", userID, value)
		return "", "", errors.New("invalid stored OTP format")
	}

	return parts[0], parts[1], nil
}

// ClearEmailChangeNewOTP removes the new email verification OTP from Redis.
func ClearEmailChangeNewOTP(ctx context.Context, userID string) error {
	logger.InfoLogger.Infof("Clearing new email change OTP for user %s", userID)

	// Get Redis client
	rdb, err := redisclient.GetRedisClient(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to init Redis client: %v", err)
		return fmt.Errorf("failed to init redis client: %w", err)
	}

	key := shared_utils.EMAIL_CHANGE_NEW_OTP_PREFIX + userID

	// Delete key
	if err := rdb.Del(ctx, key).Err(); err != nil {
		logger.ErrorLogger.Errorf("Failed to clear new email change OTP for user %s: %v", userID, err)
		return fmt.Errorf("failed to clear new email change OTP: %w", err)
	}

	return nil
}

// --- API Handlers ---

// ResendOTP API (for initial registration/email verification)
func ResendOTP(c *gin.Context) {
	logger.InfoLogger.Info("ResendOTP called (for initial email verification)")

	var request struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request body for ResendOTP: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := user_models.GetUserByEmail(c.Request.Context(), db.DB, request.Email)
	if user == nil || err != nil {
		logger.InfoLogger.Info("ResendOTP: Email not found, sending generic message.")
		c.JSON(http.StatusOK, gin.H{"message": "A verification email has been sent to your email address."})
		return
	}

	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to generate OTP in ResendOTP: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	// Use specific key prefix for initial email verification
	rdb, err := redisclient.GetRedisClient(c)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to init Redis client: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to init Redis"})
		return
	}

	ctx := c.Request.Context()
	err = rdb.Set(
		ctx,
		shared_utils.EMAIL_VERIFICATION_OTP_PREFIX+request.Email,
		utils.HashOTP(otp),
		time.Minute*time.Duration(shared_utils.OTP_EXPIRATION_MINUTES),
	).Err()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store OTP in ResendOTP for %s: %v", request.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP"})
		return
	}

	err = SendVerificationOTP(request.Email, user.FirstName, user.LastName, otp)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP"})
		return
	}

	logger.InfoLogger.Infof("OTP sent successfully to %s", request.Email)
	c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
}

// Verify OTP and return JWT token (for initial registration/email verification)
func VerifyEmail(c *gin.Context) {
	logger.InfoLogger.Info("VerifyEmail called (for initial email verification)")

	var request struct {
		Email string `json:"email" binding:"required,email"`
		OTP   string `json:"otp" binding:"required,len=6"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request for VerifyEmail: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	ctx := c.Request.Context()

	// Get Redis client once
	rdb, err := redisclient.GetRedisClient(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to init Redis client: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Redis init failed"})
		return
	}

	// Retrieve OTP hash from Redis
	key := shared_utils.EMAIL_VERIFICATION_OTP_PREFIX + request.Email
	storedHash, err := rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP expired or not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "OTP fetch failed"})
		}
		return
	}

	// Verify OTP
	if utils.HashOTP(request.OTP) != storedHash {
		logger.ErrorLogger.Errorf("Incorrect OTP for %s (initial verification)", request.Email)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect OTP"})
		return
	}

	// Fetch user
	user, err := user_models.GetUserByEmail(ctx, db.DB, request.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found or email mismatch"})
		return
	}

	// Ensure the email in the request matches the user's email
	if user.Email != request.Email {
		logger.ErrorLogger.Errorf("Email mismatch for user %s: expected %s, got %s", user.ID, user.Email, request.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email does not match user account."})
		return
	}

	// --- INTEGRATE TOKEN_VERSION HERE ---
	currentTokenVersion := user.TokenVersion

	// Generate access token
	accessToken, err := shared_models.GenerateAccessToken(user.ID, currentTokenVersion, 60*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Access token generation failed"})
		return
	}

	// Generate refresh token
	refreshToken, _, err := shared_models.GenerateRefreshTokenWithJTI(user.ID, currentTokenVersion, shared_models.REFRESH_TOKEN_EXPIRY)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Refresh token generation failed"})
		return
	}

	// Delete used OTP
	if err := rdb.Del(ctx, key).Err(); err != nil {
		logger.WarnLogger.Warnf("Failed to delete OTP for %s: %v", request.Email, err)
	}

	// Mark user as verified
	if _, err := db.DB.Exec(ctx, "UPDATE users SET is_verified_email = true WHERE id = $1", user.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user verification status"})
		return
	}

	// Store refresh token in Redis
	refreshKey := shared_utils.REFRESH_TOKEN_PREFIX + user.ID.String()
	if err := rdb.Set(ctx, refreshKey, refreshToken, time.Hour*time.Duration(shared_utils.REFRESH_TOKEN_EXP_HOURS)).Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store refresh token"})
		return
	}

	// Set JWT cookies
	if err := shared_models.SetJWTCookie(c, "access_token", accessToken, shared_models.ACCESS_TOKEN_EXPIRY, "/"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set access token cookie"})
		return
	}

	if err := shared_models.SetJWTCookie(c, "refresh_token", refreshToken, shared_models.REFRESH_TOKEN_EXPIRY, "/refresh"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set refresh token cookie"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Email verified and login successful",
	})
}

// VerifyForgotPasswordOTP function create new password
func VerifyForgotPasswordOTP(c *gin.Context) {
	logger.InfoLogger.Info("VerifyForgotPasswordOTP called")

	var request struct {
		Email       string `json:"email" binding:"required,email"`
		OTP         string `json:"otp" binding:"required,len=6"`
		NewPassword string `json:"newPassword" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request for VerifyForgotPasswordOTP: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	ctx := c.Request.Context()

	// Get Redis client once
	rdb, err := redisclient.GetRedisClient(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to init Redis client: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Redis init failed"})
		return
	}

	// Retrieve OTP hash from Redis
	key := shared_utils.FORGOT_PASSWORD_OTP_PREFIX + request.Email
	storedHash, err := rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			logger.InfoLogger.Infof("Forgot password OTP expired or not found for %s", request.Email)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP expired or not found"})
		} else {
			logger.ErrorLogger.Errorf("Failed to retrieve forgot password OTP: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during OTP verification"})
		}
		logger.ErrorLogger.Errorf("Failed to retrieve forgot password OTP from Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during OTP verification"})
		return
	}

	// Verify OTP
	if utils.HashOTP(request.OTP) != storedHash {
		logger.InfoLogger.Infof("Incorrect OTP for forgot password for %s", request.Email)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect OTP"})
		return
	}

	// Get user
	user, err := user_models.GetUserByEmail(ctx, db.DB, request.Email)
	if err != nil || user.Email != request.Email {
		logger.ErrorLogger.Errorf("User not found or email mismatch for forgot password: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found or email mismatch"})
		return
	}

	// Hash the new password
	hashedNewPassword, err := user_models.HashPassword(request.NewPassword)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to hash password for forgot password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// --- Start Transaction for Atomicity ---
	tx, err := db.DB.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Error("Failed to begin transaction for password change", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	defer tx.Rollback(ctx)

	// 1. Update password
	if _, err := tx.Exec(ctx, `UPDATE users SET password_hash = $1 WHERE id = $2`, hashedNewPassword, user.ID); err != nil {
		logger.ErrorLogger.Errorf("Failed to update password in DB for user %s: %v", user.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	// 2. Increment token_version
	if _, err := tx.Exec(ctx, `UPDATE users SET token_version = token_version + 1 WHERE id = $1`, user.ID); err != nil {
		logger.WarnLogger.Warnf("Failed to increment token_version for user %s: %v", user.Email, err)
	}

	// 3. Clear stored refresh token in Redis
	refreshKey := shared_utils.REFRESH_TOKEN_PREFIX + user.ID.String()
	if err := rdb.Del(ctx, refreshKey).Err(); err != nil {
		logger.WarnLogger.Warnf("Failed to clear refresh token for user %s: %v", user.Email, err)
	}

	// --- Commit transaction ---
	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Error("Failed to commit password change transaction", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Delete OTP from Redis
	if err := rdb.Del(ctx, key).Err(); err != nil {
		logger.WarnLogger.Warnf("Failed to delete forgot password OTP after use for %s: %v", request.Email, err)
	}

	logger.InfoLogger.Info("Password reset successful")
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successful"})
}
