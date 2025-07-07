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

	// --- TEMPORARY DEBUGGING CODE START ---
	// log.Println("Mail Package: Listing parsed template names:")
	// for _, t := range parsedTemplates.Templates() {
	// 	log.Printf("  - %s\n", t.Name())
	// }
	// --- TEMPORARY DEBUGGING CODE END ---

	log.Println("Mail Package: Templates loaded successfully.")
}

var ctx = context.Background()

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
func StoreEmailChangeNewOTP(userID, newEmail, otpHash string) error {
	logger.InfoLogger.Infof("Storing new email change OTP for user %s, new email %s", userID, newEmail)
	key := shared_utils.EMAIL_CHANGE_NEW_OTP_PREFIX + userID
	// Store newEmail along with the OTP hash
	value := fmt.Sprintf("%s:%s", otpHash, newEmail)
	err := redisclient.GetRedisClient(ctx).Set(ctx, key, value, time.Minute*shared_utils.NEW_EMAIL_OTP_EXP_MINUTES).Err()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store new email change OTP for user %s: %v", userID, err)
		return fmt.Errorf("failed to store new email change OTP: %w", err)
	}
	return nil
}

// RetrieveEmailChangeNewOTP retrieves the OTP hash and new email for verification.
// Returns (otpHash, newEmail, error)
func RetrieveEmailChangeNewOTP(userID string) (string, string, error) {
	logger.InfoLogger.Infof("Retrieving new email change OTP for user %s", userID)
	key := shared_utils.EMAIL_CHANGE_NEW_OTP_PREFIX + userID
	value, err := redisclient.GetRedisClient(ctx).Get(ctx, key).Result()
	if err != nil {
		if err.Error() == "redis: nil" {
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
func ClearEmailChangeNewOTP(userID string) error {
	logger.InfoLogger.Infof("Clearing new email change OTP for user %s", userID)
	key := shared_utils.EMAIL_CHANGE_NEW_OTP_PREFIX + userID
	err := redisclient.GetRedisClient(ctx).Del(ctx, key).Err()
	if err != nil {
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

	user, err := user_models.GetUserByEmail(ctx, db.DB, request.Email)
	if user == nil {
		logger.InfoLogger.Info("ResendOTP: Email not found, sending generic message.")
		c.JSON(http.StatusOK, gin.H{"message": "A verification email has been sent to your email address."})
		return
	}

	// Check if email exists in database (only send if it exists to avoid leaking info)
	var count int
	err = db.DB.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE email = $1", request.Email).Scan(&count)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to check email existence in ResendOTP: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
		return
	}

	if count == 0 {
		logger.InfoLogger.Info("ResendOTP: Email not found, sending generic message.")
		c.JSON(http.StatusOK, gin.H{"message": "If the email exists, an OTP has been sent."})
		return
	}

	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to generate OTP in ResendOTP: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	// Use specific key prefix for initial email verification
	err = redisclient.GetRedisClient(c).Set(ctx, shared_utils.EMAIL_VERIFICATION_OTP_PREFIX+request.Email, utils.HashOTP(otp), time.Minute*shared_utils.OTP_EXPIRATION_MINUTES).Err()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store OTP in ResendOTP for %s: %v", request.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP"})
		return
	}

	err = SendVerificationOTP(request.Email, user.FirstName, user.LastName, otp)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to send OTP in ResendOTP to %s: %v", request.Email, err)
		response := gin.H{"error": "Failed to send OTP"}
		if os.Getenv("DEBUG_MODE") == "true" {
			response["debug"] = err.Error()
		}
		c.JSON(http.StatusInternalServerError, response)
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

	// Retrieve OTP hash from Redis
	storedHash, err := redisclient.GetRedisClient(c).Get(ctx, shared_utils.EMAIL_VERIFICATION_OTP_PREFIX+request.Email).Result()
	if err != nil {
		if err.Error() == "redis: nil" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP expired or not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "OTP fetch failed"})
		}
		return
	}

	if utils.HashOTP(request.OTP) != storedHash {
		logger.ErrorLogger.Errorf("Incorrect OTP for %s (initial verification)", request.Email)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect OTP"})
		return
	}

	user, err := user_models.GetUserByEmail(context.Background(), db.DB, request.Email)
	if err != nil || user.Email != request.Email {
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

	currentTokenVersion := user.TokenVersion // Get the current token_version from the user object

	// Generate access token (60 minutes) including token_version
	accessToken, err := shared_models.GenerateAccessToken(user.ID, currentTokenVersion, 60*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Access token generation failed"})
		return
	}

	refreshToken, err := shared_models.GenerateRefreshToken(user.ID, user.TokenVersion, 30*24*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Refresh token generation failed"})
		return
	}

	// Delete used OTP
	_ = redisclient.GetRedisClient(c).Del(ctx, shared_utils.EMAIL_VERIFICATION_OTP_PREFIX+request.Email).Err()

	// Mark user as verified
	_, err = db.DB.Exec(ctx, "UPDATE users SET is_verified_email = true WHERE id = $1", user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user verification status"})
		return
	}

	// Store refresh token in Redis
	err = redisclient.GetRedisClient(c).Set(
		ctx,
		shared_utils.USER_REFRESH_TOKEN_PREFIX+user.ID.String(),
		refreshToken,
		time.Hour*shared_utils.REFRESH_TOKEN_EXP_HOURS,
	).Err()
	if err != nil {
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

	// No tokens in response if you use cookies
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

	// Retrieve OTP hash from Redis using the password reset key
	storedHash, err := redisclient.GetRedisClient(c).Get(ctx, shared_utils.FORGOT_PASSWORD_OTP_PREFIX+request.Email).Result()
	if err != nil {
		if err.Error() == "redis: nil" {
			logger.ErrorLogger.Info(fmt.Sprintf("Forgot password OTP expired or not found for %s", request.Email))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP expired or not found"})
			return
		}
		logger.ErrorLogger.Errorf("Failed to retrieve forgot password OTP from Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during OTP verification"})
		return
	}

	// Verify OTP
	if utils.HashOTP(request.OTP) != storedHash {
		logger.ErrorLogger.Info(fmt.Sprintf("Incorrect OTP for forgot password for %s", request.Email))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect OTP"})
		return
	}

	// Get user
	user, err := user_models.GetUserByEmail(context.Background(), db.DB, request.Email)
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
	tx, err := db.DB.Begin(context.Background())
	if err != nil {
		logger.ErrorLogger.Error("Failed to begin transaction for password change", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	defer tx.Rollback(context.Background()) // Rollback on error

	// 1. Update the password in the database
	_, err = tx.Exec(context.Background(), `UPDATE users SET password_hash = $1 WHERE id = $2`, hashedNewPassword, user.ID)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to update password in DB for user %s: %w", user.Email, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	// 2. Increment the token_version
	_, err = tx.Exec(context.Background(), `UPDATE users SET token_version = token_version + 1 WHERE id = $1`, user.ID)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to increment token version for user %s: %w", user.Email, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke old tokens"})
		return
	}

	// 3. Optionally, clear the refresh_token field in the database
	// This immediately invalidates the stored refresh token as well.
	key := shared_utils.USER_REFRESH_TOKEN_PREFIX + user.ID.String()
	err = redisclient.GetRedisClient(ctx).Del(ctx, key).Err()
	if err != nil {
		logger.WarnLogger.Warn(fmt.Errorf("failed to clear refresh token for user %s: %w", user.Email, err))
		// This is a warning because even if clearing fails, incrementing token_version still revokes.
		// But it's good practice to clear the old token too.
	}

	// --- Commit Transaction ---
	if err := tx.Commit(context.Background()); err != nil {
		logger.ErrorLogger.Error("Failed to commit password change transaction", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Delete OTP from Redis
	if err := redisclient.GetRedisClient(c).Del(ctx, shared_utils.FORGOT_PASSWORD_OTP_PREFIX+request.Email).Err(); err != nil {
		logger.ErrorLogger.Warnf("Failed to delete forgot password OTP after use for %s: %v", request.Email, err)
	}

	logger.InfoLogger.Info("Password reset successful")

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset successful",
	})
}
