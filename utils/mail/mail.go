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
	"github.com/joy095/identity/models/customer_models"
	"github.com/joy095/identity/models/shared_models"
	"github.com/joy095/identity/models/user_models"
	"github.com/joy095/identity/utils"
	"github.com/joy095/identity/utils/shared_utils"
	gomail "gopkg.in/gomail.v2" // Import gomail
)

const (
	ForgotPasswordTemplate      = "templates/email/forgot_password_otp.html"
	EmailVerificationTemplate   = "templates/email/email_verification_otp.html"
	VerifyNewEmailOTPTemplate   = "templates/email/verify_new_email_otp.html"
	CustomerLoginTemplate       = "templates/email/customer_otp_login.html"
	CustomerVerifyEmailTemplate = "templates/email/customer_verify_email_otp.html"
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
	log.Println("Mail Package: Listing parsed template names:")
	for _, t := range parsedTemplates.Templates() {
		log.Printf("  - %s\n", t.Name())
	}
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

// SendCustomerOTP sends an OTP to a customer.
func SendCustomerOTP(emailAddress, otp string, templatePath string) error {
	logger.InfoLogger.Infof("SendCustomerOTP called to %s using template %s", emailAddress, templatePath)

	var customer customer_models.Customer                                              // Assuming models.Customer has Email and ID
	query := `SELECT id, email, first_name, last_name FROM customers WHERE email = $1` // Include names if available
	err := db.DB.QueryRow(ctx, query, emailAddress).Scan(&customer.ID, &customer.Email, &customer.FirstName, &customer.LastName)
	if err != nil {
		logger.ErrorLogger.Errorf("Customer not found for sending OTP to %s: %v", emailAddress, err)
		return fmt.Errorf("customer not found: %w", err)
	}

	// Store OTP using email as key for customer OTPs
	// Using a generic "otp:" prefix for customer OTPs if no specific prefix is defined for them
	err = redisclient.GetRedisClient().Set(ctx, shared_utils.CUSTOMER_OTP_PREFIX+emailAddress, utils.HashOTP(otp), time.Minute*shared_utils.OTP_EXPIRATION_MINUTES).Err()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store customer OTP for %s: %v", emailAddress, err)
		return fmt.Errorf("failed to store OTP: %w", err)
	}

	data := struct {
		FirstName *string
		LastName  *string
		OTP       string
		Year      int
	}{
		FirstName: customer.FirstName, // Use customer's first name
		LastName:  customer.LastName,  // Use customer's last name
		OTP:       otp,
		Year:      time.Now().Year(),
	}

	return sendEmail(customer.Email, "Your OTP Code", templatePath, data)
}

// StoreEmailChangeNewOTP stores the OTP in Redis for the new email address verification.
func StoreEmailChangeNewOTP(userID, newEmail, otpHash string) error {
	logger.InfoLogger.Infof("Storing new email change OTP for user %s, new email %s", userID, newEmail)
	key := shared_utils.EMAIL_CHANGE_NEW_OTP_PREFIX + userID
	// Store newEmail along with the OTP hash
	value := fmt.Sprintf("%s:%s", otpHash, newEmail)
	err := redisclient.GetRedisClient().Set(ctx, key, value, time.Minute*shared_utils.NEW_EMAIL_OTP_EXP_MINUTES).Err()
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
	value, err := redisclient.GetRedisClient().Get(ctx, key).Result()
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
	err := redisclient.GetRedisClient().Del(ctx, key).Err()
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
		Email     string `json:"email" binding:"required,email"`
		FirstName string `json:"firstName" binding:"required"`
		LastName  string `json:"lastName" binding:"required"`
		Username  string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request body for ResendOTP: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if email exists in database (only send if it exists to avoid leaking info)
	var count int
	err := db.DB.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE email = $1", request.Email).Scan(&count)
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
	err = redisclient.GetRedisClient().Set(ctx, shared_utils.EMAIL_VERIFICATION_OTP_PREFIX+request.Username, utils.HashOTP(otp), time.Minute*shared_utils.OTP_EXPIRATION_MINUTES).Err()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store OTP in ResendOTP for %s: %v", request.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP"})
		return
	}

	err = SendVerificationOTP(request.Email, request.FirstName, request.LastName, otp)
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
		Email    string `json:"email" binding:"required,email"`
		OTP      string `json:"otp" binding:"required,len=6"`
		Username string `json:"username"` // Assuming username is part of the request
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request for VerifyEmail: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	request.Username = strings.ToLower(strings.TrimSpace(request.Username))

	// Retrieve OTP hash from Redis using the specific prefix for initial verification
	storedHash, err := redisclient.GetRedisClient().Get(ctx, shared_utils.EMAIL_VERIFICATION_OTP_PREFIX+request.Username).Result()
	if err != nil {
		if err.Error() == "redis: nil" {
			logger.ErrorLogger.Errorf("OTP expired or not found for %s (initial verification)", request.Email)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP expired or not found"})
			return
		}
		logger.ErrorLogger.Errorf("Failed to retrieve OTP from Redis in VerifyEmail: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during OTP verification"})
		return
	}

	// Verify OTP
	if utils.HashOTP(request.OTP) != storedHash {
		logger.ErrorLogger.Errorf("Incorrect OTP for %s (initial verification)", request.Email)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect OTP"})
		return
	}

	// Get user by email to retrieve userID and token_version
	user, err := user_models.GetUserByUsername(db.DB, request.Username) // Assuming username is provided and used to fetch user
	if err != nil {
		logger.ErrorLogger.Errorf("User not found for username %s: %v", request.Username, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
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
		logger.ErrorLogger.Error("Failed to generate access token in VerifyEmail")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	// Generate refresh token (30 days) including token_version
	refreshToken, err := shared_models.GenerateRefreshToken(user.ID, currentTokenVersion, 30*24*time.Hour) // Refresh Token expires in 30 days
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate refresh token in VerifyEmail")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}
	// --- END TOKEN_VERSION INTEGRATION ---

	// Delete OTP from Redis after successful verification
	if err := redisclient.GetRedisClient().Del(ctx, shared_utils.EMAIL_VERIFICATION_OTP_PREFIX+request.Username).Err(); err != nil {
		logger.ErrorLogger.Warnf("Failed to delete initial verification OTP from Redis for %s: %v", request.Username, err)
	}

	_, err = db.DB.Exec(ctx,
		"UPDATE users SET is_verified_email = true WHERE id = $1",
		user.ID,
	)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update user data (is_verified_email) for user %s: %v", user.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user data"})
		return
	}

	// USER_REFRESH_TOKEN_PREFIX
	// err := redisclient.GetRedisClient().Set(ctx, key, hashedOTP, 10*time.Minute).Err()
	err = redisclient.GetRedisClient().Set(ctx, shared_utils.USER_REFRESH_TOKEN_PREFIX+user.ID.String(), refreshToken, time.Hour*shared_utils.REFRESH_TOKEN_EXP_HOURS).Err()

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store refresh token in Redis for user %s: %v", user.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store refresh token"})
		return
	}
	logger.InfoLogger.Infof("Email verified and tokens generated successfully for user %s", user.ID)

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
		"message":      "Email verified and logged in successfully!",
	})
}

// VerifyForgotPasswordOTP function create new password
func VerifyForgotPasswordOTP(c *gin.Context) {
	logger.InfoLogger.Info("VerifyForgotPasswordOTP called")

	var request struct {
		Email       string `json:"email" binding:"required,email"`
		OTP         string `json:"otp" binding:"required,len=6"` // Assuming 6-digit OTP
		NewPassword string `json:"newPassword" binding:"required,min=8"`
		Username    string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request for VerifyForgotPasswordOTP: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	request.Email = strings.ToLower(strings.TrimSpace(request.Email))

	// Retrieve OTP hash from Redis using the password reset key
	storedHash, err := redisclient.GetRedisClient().Get(ctx, shared_utils.FORGOT_PASSWORD_OTP_PREFIX+request.Username).Result()
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
	user, err := user_models.GetUserByUsername(db.DB, request.Username)
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
		logger.ErrorLogger.Error(fmt.Errorf("failed to update password in DB for user %s: %w", user.Username, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	// 2. Increment the token_version
	_, err = tx.Exec(context.Background(), `UPDATE users SET token_version = token_version + 1 WHERE id = $1`, user.ID)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to increment token version for user %s: %w", user.Username, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke old tokens"})
		return
	}

	// 3. Optionally, clear the refresh_token field in the database
	// This immediately invalidates the stored refresh token as well.
	_, err = tx.Exec(context.Background(), `UPDATE users SET refresh_token = NULL WHERE id = $1`, user.ID)
	if err != nil {
		logger.WarnLogger.Warn(fmt.Errorf("failed to clear refresh token for user %s: %w", user.Username, err))
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
	if err := redisclient.GetRedisClient().Del(ctx, shared_utils.FORGOT_PASSWORD_OTP_PREFIX+request.Username).Err(); err != nil {
		logger.ErrorLogger.Warnf("Failed to delete forgot password OTP after use for %s: %v", request.Email, err)
	}

	logger.InfoLogger.Info("Password reset successful")

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset successful",
	})
}

// Send OTP to customer for login
func SendCustomerLoginOTP(c *gin.Context) {
	logger.InfoLogger.Info("SendCustomerLoginOTP called")

	var request struct {
		Email string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request for SendCustomerLoginOTP: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if customer exists
	var count int
	err := db.DB.QueryRow(ctx, "SELECT COUNT(*) FROM customers WHERE email = $1", request.Email).Scan(&count)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to check customer existence for login OTP: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
		return
	}
	if count == 0 {
		logger.InfoLogger.Info("Customer not found for login OTP, sending generic response.")
		c.JSON(http.StatusOK, gin.H{"message": "If the email exists, an OTP has been sent."})
		return
	}

	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to generate OTP in SendCustomerLoginOTP: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	err = SendCustomerOTP(request.Email, otp, CustomerLoginTemplate) // Use the constant
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to send customer login OTP to %s: %v", request.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP"})
		return
	}

	logger.InfoLogger.Infof("Customer login OTP sent successfully to %s", request.Email)
	c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
}
