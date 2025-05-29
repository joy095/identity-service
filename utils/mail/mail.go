package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config"
	"github.com/joy095/identity/config/db"
	redisclient "github.com/joy095/identity/config/redis"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models" // Assuming models.User and models.Customer are defined here
	"github.com/joy095/identity/utils"
	gomail "gopkg.in/gomail.v2" // Import gomail
)

// Define durations for OTPs and tokens
const (
	OTP_EXPIRATION_MINUTES         = 10
	EMAIL_CHANGE_CONFIRM_EXP_HOURS = 24 // Confirmation link valid for 24 hours
	NEW_EMAIL_OTP_EXP_MINUTES      = 10 // OTP for new email valid for 10 minutes
)

// Redis Key Prefixes
const (
	FORGOT_PASSWORD_OTP_PREFIX    = "forgot_password_otp:"
	EMAIL_VERIFICATION_OTP_PREFIX = "email_verification_otp:"
	EMAIL_CHANGE_NEW_OTP_PREFIX   = "email_change_new_otp:" // For verifying the new email

	CUSTOMER_OTP_PREFIX = "customer_otp:"
)

// Email template paths
const (
	forgotPasswordTemplate    = "templates/email/forgot_password_otp.html"
	emailVerificationTemplate = "templates/email/email_verification_otp.html"

	verifyNewEmailOTPTemplate = "templates/email/verify_new_email_otp.html" // New template
	customerLoginTemplate     = "templates/email/customer_otp_login.html"   // Customer login template
	userRegistrationTemplate  = "templates/email/otp_template.html"         // User registration template
)

var ctx = context.Background()
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

// ErrOTPNotFound is returned when an OTP is not found or expired.
var ErrOTPNotFound = errors.New("otp not found or expired")

func init() {
	config.LoadEnv()
}

// --- Helper function to send email using gomail ---
func sendEmail(toEmail, subject, templatePath string, data interface{}) error {
	mailer := gomail.NewMessage()
	mailer.SetHeader("From", os.Getenv("FROM_EMAIL"))
	mailer.SetHeader("To", toEmail)
	mailer.SetHeader("Subject", subject)

	t, err := template.ParseFiles(templatePath)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to parse email template %s: %v", templatePath, err)
		return fmt.Errorf("failed to parse email template: %w", err)
	}

	var body bytes.Buffer
	if err := t.Execute(&body, data); err != nil {
		logger.ErrorLogger.Errorf("Failed to execute email template %s: %v", templatePath, err)
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	mailer.SetBody("text/html", body.String())

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

	// Log that the SMTP server is about to be connected
	logger.InfoLogger.Printf("Attempting to connect to SMTP server: %s:%d", smtpHost, port)

	if err := dialer.DialAndSend(mailer); err != nil {
		logger.ErrorLogger.Errorf("Failed to send email to %s: %v", toEmail, err)
		return fmt.Errorf("failed to send email: %w", err)
	}

	// Log successful connection and email sending
	logger.InfoLogger.Printf("Successfully connected to SMTP server and sent email to %s", toEmail)
	return nil
}

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
	return sendEmail(email, "Password Reset OTP", forgotPasswordTemplate, data)
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
	return sendEmail(email, "Verify Your Email Address", emailVerificationTemplate, data)
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
	return sendEmail(newEmail, "Verify Your New Email Address", verifyNewEmailOTPTemplate, data)
}

// SendCustomerOTP sends an OTP to a customer.
func SendCustomerOTP(emailAddress, otp string, templatePath string) error {
	logger.InfoLogger.Infof("SendCustomerOTP called to %s using template %s", emailAddress, templatePath)

	var customer models.Customer                                                       // Assuming models.Customer has Email and ID
	query := `SELECT id, email, first_name, last_name FROM customers WHERE email = $1` // Include names if available
	err := db.DB.QueryRow(ctx, query, emailAddress).Scan(&customer.ID, &customer.Email, &customer.FirstName, &customer.LastName)
	if err != nil {
		logger.ErrorLogger.Errorf("Customer not found for sending OTP to %s: %v", emailAddress, err)
		return fmt.Errorf("customer not found: %w", err)
	}

	// Store OTP using email as key for customer OTPs
	// Using a generic "otp:" prefix for customer OTPs if no specific prefix is defined for them
	err = redisclient.GetRedisClient().Set(ctx, CUSTOMER_OTP_PREFIX+emailAddress, utils.HashOTP(otp), time.Minute*OTP_EXPIRATION_MINUTES).Err()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store customer OTP for %s: %v", emailAddress, err)
		return fmt.Errorf("failed to store OTP: %w", err)
	}

	data := struct {
		FirstName string
		LastName  string
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
	key := EMAIL_CHANGE_NEW_OTP_PREFIX + userID
	// Store newEmail along with the OTP hash
	value := fmt.Sprintf("%s:%s", otpHash, newEmail)
	err := redisclient.GetRedisClient().Set(ctx, key, value, time.Minute*NEW_EMAIL_OTP_EXP_MINUTES).Err()
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
	key := EMAIL_CHANGE_NEW_OTP_PREFIX + userID
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
	key := EMAIL_CHANGE_NEW_OTP_PREFIX + userID
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
	err = redisclient.GetRedisClient().Set(ctx, EMAIL_VERIFICATION_OTP_PREFIX+request.Username, utils.HashOTP(otp), time.Minute*OTP_EXPIRATION_MINUTES).Err()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store OTP in ResendOTP for %s: %v", request.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP"})
		return
	}

	err = SendVerificationOTP(request.Email, request.FirstName, request.LastName, otp)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to send OTP in ResendOTP to %s: %v", request.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to send OTP",
			"debug": err.Error(),
		})
		return
	}

	logger.InfoLogger.Infof("OTP sent successfully to %s", request.Email)
	c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
}

// Verify OTP and return JWT token (for initial registration/email verification)
func VerifyOTP(c *gin.Context) {
	logger.InfoLogger.Info("VerifyOTP called (for initial email verification)")

	var request struct {
		Email    string `json:"email" binding:"required,email"`
		OTP      string `json:"otp" binding:"required,len=6"`
		Username string `json:"username"` // Assuming username is part of the request
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request for VerifyOTP: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	request.Email = strings.ToLower(strings.TrimSpace(request.Email))

	// Retrieve OTP hash from Redis using the specific prefix for initial verification
	storedHash, err := redisclient.GetRedisClient().Get(ctx, EMAIL_VERIFICATION_OTP_PREFIX+request.Username).Result()
	if err != nil {
		if err.Error() == "redis: nil" {
			logger.ErrorLogger.Info(fmt.Sprintf("OTP expired or not found for %s (initial verification)", request.Email))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP expired or not found"})
			return
		}
		logger.ErrorLogger.Errorf("Failed to retrieve OTP from Redis in VerifyOTP: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during OTP verification"})
		return
	}

	// Verify OTP
	if utils.HashOTP(request.OTP) != storedHash {
		logger.ErrorLogger.Info(fmt.Sprintf("Incorrect OTP for %s (initial verification)", request.Email))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect OTP"})
		return
	}

	// Get user by email to retrieve userID
	user, err := models.GetUserByUsername(db.DB, request.Username) // Assuming username is provided and used to fetch user
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

	// Generate access token (60 minutes)
	accessToken, err := models.GenerateAccessToken(user.ID, 60*time.Minute)
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate access token in VerifyOTP")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	// Generate refresh token (7 days)
	refreshToken, err := models.GenerateRefreshToken(user.ID, 30*24*time.Hour) // Refresh Token expires in 30 days
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate refresh token in VerifyOTP")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	// Delete OTP from Redis after successful verification
	if err := redisclient.GetRedisClient().Del(ctx, EMAIL_VERIFICATION_OTP_PREFIX+request.Username).Err(); err != nil {
		logger.ErrorLogger.Warnf("Failed to delete initial verification OTP from Redis for %s: %v", request.Username, err)
	}

	// Update user's email verification and refresh token in DB
	_, err = db.DB.Exec(ctx,
		"UPDATE users SET is_verified_email = true, refresh_token = $1 WHERE id = $2",
		refreshToken, user.ID) // Update by ID, as username might not be unique if email changes later
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update user data (is_verified_email, refresh_token) for user %s: %v", user.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user data"})
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
	storedHash, err := redisclient.GetRedisClient().Get(ctx, FORGOT_PASSWORD_OTP_PREFIX+request.Username).Result()
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
	user, err := models.GetUserByUsername(db.DB, request.Username)
	if err != nil || user.Email != request.Email {
		logger.ErrorLogger.Errorf("User not found or email mismatch for forgot password: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found or email mismatch"})
		return
	}

	// Hash the new password
	hashedPassword, err := models.HashPassword(request.NewPassword)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to hash password for forgot password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Update user's password
	_, err = db.DB.Exec(ctx, "UPDATE users SET password_hash = $1 WHERE id = $2", hashedPassword, user.ID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update password for user %s: %v", user.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	// Delete OTP from Redis
	if err := redisclient.GetRedisClient().Del(ctx, FORGOT_PASSWORD_OTP_PREFIX+request.Username).Err(); err != nil {
		logger.ErrorLogger.Warnf("Failed to delete forgot password OTP after use for %s: %v", request.Email, err)
	}

	logger.InfoLogger.Info("Password reset successful")

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset successful",
	})
}

// Verify Customer OTP for for account and return JWT token
func VerifyCustomerOTP(c *gin.Context) {
	logger.InfoLogger.Info("VerifyCustomerOTP called")

	var request struct {
		Email string `json:"email" binding:"required,email"`
		OTP   string `json:"otp" binding:"required,len=6"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request for VerifyCustomerOTP: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	request.Email = strings.ToLower(strings.TrimSpace(request.Email))

	// Retrieve OTP hash from Redis (using generic "otp:" prefix for customer login/verification)
	// You might want to define a specific prefix for customer OTPs like `CUSTOMER_OTP_PREFIX`
	storedHash, err := redisclient.GetRedisClient().Get(ctx, CUSTOMER_OTP_PREFIX+request.Email).Result()
	if err != nil {
		if err.Error() == "redis: nil" {
			logger.ErrorLogger.Info(fmt.Sprintf("Customer OTP expired or not found for %s", request.Email))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP expired or not found"})
			return
		}
		logger.ErrorLogger.Errorf("Failed to retrieve customer OTP from Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during OTP verification"})
		return
	}

	// Verify OTP
	if utils.HashOTP(request.OTP) != storedHash {
		logger.ErrorLogger.Info(fmt.Sprintf("Incorrect OTP for customer %s", request.Email))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect OTP"})
		return
	}

	// Get customer by email to retrieve ID
	customer, err := models.GetCustomerByEmail(db.DB, request.Email)
	if err != nil {
		logger.ErrorLogger.Errorf("Customer not found for email %s: %v", request.Email, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Customer not found"})
		return
	}

	// Generate access token (60 minutes)
	accessToken, err := models.GenerateAccessToken(customer.ID, 60*time.Minute)
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate access token for customer")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	// Generate refresh token (7 days)
	refreshToken, err := models.GenerateRefreshToken(customer.ID, 30*24*time.Hour) // Refresh Token expires in 30 days
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate refresh token for customer")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	// Delete OTP from Redis after successful verification
	if err := redisclient.GetRedisClient().Del(ctx, CUSTOMER_OTP_PREFIX+request.Email).Err(); err != nil {
		logger.ErrorLogger.Warnf("Failed to delete customer OTP from Redis for %s: %v", request.Email, err)
	}

	// Update customer's email verification and refresh token in DB
	_, err = db.DB.Exec(ctx,
		"UPDATE customers SET is_verified_email = true, refresh_token = $1 WHERE id = $2",
		refreshToken, customer.ID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update customer data for %s: %v", customer.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update customer data"})
		return
	}

	logger.InfoLogger.Infof("Customer email verified and tokens generated successfully for customer %s", customer.ID)

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
		"message":      "Customer email verified and logged in successfully!",
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

	err = SendCustomerOTP(request.Email, otp, customerLoginTemplate) // Use the constant
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to send customer login OTP to %s: %v", request.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP"})
		return
	}

	logger.InfoLogger.Infof("Customer login OTP sent successfully to %s", request.Email)
	c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
}
