package mail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joy095/identity/config"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models" // Assuming models.User and models.Customer are defined here
	"github.com/joy095/identity/utils"

	"github.com/gin-gonic/gin"
	redisclient "github.com/joy095/identity/config/redis"
	mail "github.com/xhit/go-simple-mail/v2"
)

var ctx = context.Background()
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func init() {
	config.LoadEnv()
}

// Create a new SMTP client connection
func newSMTPClient() (*mail.SMTPClient, error) {
	server := mail.NewSMTPClient()
	server.Host = os.Getenv("SMTP_HOST")
	server.Port, _ = strconv.Atoi(os.Getenv("SMTP_PORT"))
	server.Username = os.Getenv("SMTP_USERNAME")
	server.Password = os.Getenv("SMTP_PASSWORD")
	server.Encryption = mail.EncryptionTLS
	server.KeepAlive = false
	server.ConnectTimeout = 10 * time.Second
	server.SendTimeout = 10 * time.Second

	return server.Connect()
}

// StoreOTP hash in Redis with expiration
// key can be "otp:email", "password_reset_otp:username-email", "email_change_otp:userID"
func StoreOTP(key string, otp string) error {
	hashedOTP := utils.HashOTP(otp)
	return redisclient.GetRedisClient().Set(context.Background(), key, hashedOTP, 10*time.Minute).Err()
}

// RetrieveOTP hash from Redis
func RetrieveOTP(key string) (string, error) {
	storedHash, err := redisclient.GetRedisClient().Get(ctx, key).Result()
	if err != nil {
		return "", errors.New("OTP expired or not found")
	}
	return storedHash, nil
}

// ClearOTP from Redis
func ClearOTP(key string) error {
	return redisclient.GetRedisClient().Del(ctx, key).Err()
}

// ErrOTPNotFound is returned when an OTP is not found or expired.
var ErrOTPNotFound = errors.New("otp not found or expired")

// StoreEmailChangeOTP stores the OTP and new email for verification using Redis.
// The key is based on userID to correctly associate the pending email change with the user.
func StoreEmailChangeOTP(userID string, newEmail string, otp string) error {
	keyEmail := fmt.Sprintf("email_change_otp:%s:email", userID)
	keyOTP := fmt.Sprintf("email_change_otp:%s:otp", userID)
	expiry := 10 * time.Minute

	// Store the new email
	err := redisclient.GetRedisClient().Set(context.Background(), keyEmail, newEmail, expiry).Err()
	if err != nil {
		return fmt.Errorf("failed to store new email for verification: %w", err)
	}

	// Store the hashed OTP
	hashedOTP := utils.HashOTP(otp)
	err = redisclient.GetRedisClient().Set(context.Background(), keyOTP, hashedOTP, expiry).Err()
	if err != nil {
		// Attempt to clean up the email key if OTP storage fails
		redisclient.GetRedisClient().Del(context.Background(), keyEmail)
		return fmt.Errorf("failed to store OTP for email change: %w", err)
	}
	return nil
}

// RetrieveEmailChangeOTP retrieves the stored OTP hash and new email for verification from Redis.
func RetrieveEmailChangeOTP(userID string) (string, string, error) {
	keyEmail := fmt.Sprintf("email_change_otp:%s:email", userID)
	keyOTP := fmt.Sprintf("email_change_otp:%s:otp", userID)

	newEmail, err := redisclient.GetRedisClient().Get(context.Background(), keyEmail).Result()
	if err != nil {
		return "", "", ErrOTPNotFound
	}

	storedHash, err := redisclient.GetRedisClient().Get(context.Background(), keyOTP).Result()
	if err != nil {
		// If OTP is not found but email is, it's still an OTP issue. Clean up email.
		redisclient.GetRedisClient().Del(context.Background(), keyEmail)
		return "", "", ErrOTPNotFound
	}
	return storedHash, newEmail, nil
}

// ClearEmailChangeOTP removes the stored OTP and new email after successful verification from Redis.
func ClearEmailChangeOTP(userID string) error {
	keyEmail := fmt.Sprintf("email_change_otp:%s:email", userID)
	keyOTP := fmt.Sprintf("email_change_otp:%s:otp", userID)
	err1 := redisclient.GetRedisClient().Del(context.Background(), keyEmail).Err()
	err2 := redisclient.GetRedisClient().Del(context.Background(), keyOTP).Err()
	if err1 != nil || err2 != nil {
		return fmt.Errorf("failed to clear email change OTP from Redis: email err: %w, otp err: %w", err1, err2)
	}
	return nil
}

// SendEmailChangeOTP sends an OTP to the user's new email for verification.
func SendEmailChangeOTP(email, firstName, lastName, otp string) error {
	logger.InfoLogger.Infof("SendEmailChangeOTP called to %s for user %s %s", email, firstName, lastName)

	tmpl, err := template.ParseFiles("templates/email_change_otp.html") // Ensure this template exists
	if err != nil {
		return fmt.Errorf("failed to parse email change OTP template: %w", err)
	}

	var body bytes.Buffer
	data := struct {
		FirstName string
		LastName  string
		OTP       string
		Year      int
	}{
		FirstName: strings.TrimSpace(firstName),
		LastName:  strings.TrimSpace(lastName),
		OTP:       otp,
		Year:      time.Now().Year(),
	}

	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute email change template: %w", err)
	}

	smtpClient, err := newSMTPClient()
	if err != nil {
		logger.ErrorLogger.Errorf("failed to connect to SMTP server: %v", err)
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer smtpClient.Close()

	emailMsg := mail.NewMSG()
	emailMsg.SetFrom(os.Getenv("FROM_EMAIL")).
		AddTo(email). // Send to the NEW email address
		SetSubject("Verify Your New Email Address").
		SetBody(mail.TextHTML, body.String())

	logger.InfoLogger.Info("Sending email change OTP email to: ", email)

	return emailMsg.Send(smtpClient)
}

// SendOTP sends an OTP for initial registration/verification.
func SendOTP(emailAddress, firstName, lastName, otp string) error {
	logger.InfoLogger.Info("SendOTP called on mail (for user registration)")

	var user models.User // Changed from models.Customer for user registration context
	// Assuming `users` table contains first_name and last_name
	query := `SELECT id, email, first_name, last_name FROM users WHERE email = $1`

	err := db.DB.QueryRow(context.Background(), query, emailAddress).Scan(&user.ID, &user.Email, &user.FirstName, &user.LastName)
	if err != nil {
		return err
	}

	// Store OTP using the email as key
	if err := StoreOTP("otp:"+emailAddress, otp); err != nil {
		return err
	}

	tmpl, err := template.ParseFiles("templates/otp_template.html")
	if err != nil {
		return err
	}

	var body bytes.Buffer
	data := struct {
		FirstName string
		LastName  string
		OTP       string
		Year      int
	}{
		FirstName: strings.TrimSpace(firstName),
		LastName:  strings.TrimSpace(lastName),
		OTP:       otp,
		Year:      time.Now().Year(),
	}

	if err := tmpl.Execute(&body, data); err != nil {
		return err
	}

	smtpClient, err := newSMTPClient()
	if err != nil {
		logger.ErrorLogger.Errorf("failed to connect to SMTP server: %v", err)
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer smtpClient.Close()

	emailMsg := mail.NewMSG()
	emailMsg.SetFrom(os.Getenv("FROM_EMAIL")).
		AddTo(user.Email).
		SetSubject("Your OTP Code").
		SetBody(mail.TextHTML, body.String())

	logger.InfoLogger.Info("Sending OTP email to: ", user.Email)

	return emailMsg.Send(smtpClient)
}

// SendForgotPasswordOTP sends an OTP to the provided email address for password reset.
func SendForgotPasswordOTP(emailAddress, otp string) error {
	logger.InfoLogger.Info("SendForgotPasswordOTP called on mail")

	var user models.User
	query := `SELECT id, email, first_name, last_name, username FROM users WHERE email = $1` // Include first_name, last_name, username
	err := db.DB.QueryRow(context.Background(), query, emailAddress).Scan(&user.ID, &user.Email, &user.FirstName, &user.LastName, &user.Username)
	if err != nil {
		return err
	}

	// Store OTP using a key that includes username and email for password reset
	if err := StoreOTP("forgot_password_otp:"+user.Username+"-"+user.Email, otp); err != nil {
		return err
	}

	tmpl, err := template.ParseFiles("templates/forgot_password_otp.html")
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}

	var body bytes.Buffer
	data := struct {
		FirstName string
		LastName  string
		OTP       string
		Year      int
	}{
		FirstName: user.FirstName,
		LastName:  user.LastName,
		OTP:       otp,
		Year:      time.Now().Year(),
	}

	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	smtpClient, err := newSMTPClient()
	if err != nil {
		logger.ErrorLogger.Errorf("failed to connect to SMTP server: %v", err)
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer smtpClient.Close()

	emailMsg := mail.NewMSG()
	emailMsg.SetFrom(os.Getenv("FROM_EMAIL")).
		AddTo(user.Email).
		SetSubject("Reset Your Password - OTP").
		SetBody(mail.TextHTML, body.String())

	logger.InfoLogger.Infof("Sending password reset OTP email to: %s", user.Email)

	return emailMsg.Send(smtpClient)
}

// Request OTP API (for initial registration/email verification)
func RequestOTP(c *gin.Context) {
	logger.InfoLogger.Info("RequestOTP called on mail")

	var request struct {
		Email     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request body")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if request.Email == "" {
		logger.ErrorLogger.Error("Email is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email is required"})
		return
	}

	// Check if email exists in database
	var count int
	err := db.DB.QueryRow(context.Background(), "SELECT COUNT(*) FROM users WHERE email = $1", request.Email).Scan(&count)
	if err != nil {
		logger.ErrorLogger.Error("Failed to process request")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
		return
	}

	if count == 0 {
		logger.InfoLogger.Info("If the email exists, an OTP has been sent")
		c.JSON(http.StatusOK, gin.H{"message": "If the email exists, an OTP has been sent"})
		return
	}

	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	// Use generic StoreOTP
	err = StoreOTP("otp:"+request.Email, otp)
	if err != nil {
		logger.ErrorLogger.Error("Failed to store OTP in RequestOTP")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP"})
		return
	}

	err = SendOTP(request.Email, request.FirstName, request.LastName, otp)
	if err != nil {
		logger.ErrorLogger.Error("Failed to send OTP")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP"})
		return
	}

	logger.InfoLogger.Info("OTP send successfully")
	c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
}

// Verify OTP and return JWT token (for initial registration/email verification)
func VerifyOTP(c *gin.Context) {
	logger.InfoLogger.Info("VerifyOTP called on mail")

	var request struct {
		Email    string `json:"email"`
		OTP      string `json:"otp"`
		Username string `json:"username"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	if request.Email == "" || request.OTP == "" {
		logger.ErrorLogger.Error("Email and OTP are required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email and OTP are required"})
		return
	}

	// Retrieve OTP hash from Redis using the key "otp:email"
	storedHash, err := RetrieveOTP("otp:" + request.Email)
	if err != nil {
		logger.ErrorLogger.Error("OTP expired or not found")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP expired or not found"})
		return
	}

	// Verify OTP
	if utils.HashOTP(request.OTP) != storedHash {
		logger.ErrorLogger.Error("Incorrect OTP")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect OTP"})
		return
	}

	// Get user by email to retrieve userID
	user, err := models.GetUserByUsername(db.DB, request.Username)
	if err != nil {
		logger.ErrorLogger.Errorf("User not found: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Generate access token (60 minutes)
	accessToken, err := models.GenerateAccessToken(user.ID, 60*time.Minute)
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate access token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	// Generate refresh token (7 days)
	refreshToken, err := models.GenerateRefreshToken(user.ID, 30*24*time.Hour) // Refresh Token expires in 30 days
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate refresh token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	// Delete OTP from Redis after successful verification
	if err := ClearOTP("otp:" + request.Email); err != nil {
		logger.ErrorLogger.Error("Failed to delete OTP from Redis")
	}

	// Update user's email verification and refresh token in DB
	_, err = db.DB.Exec(context.Background(),
		"UPDATE users SET is_verified_email = true, refresh_token = $1 WHERE email = $2 AND username = $3",
		refreshToken, request.Email, request.Username)
	if err != nil {
		logger.ErrorLogger.Error("Failed to update user data")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user data"})
		return
	}

	logger.InfoLogger.Info("Email verified and tokens generated successfully")

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
	})
}

// VerifyForgotPasswordOTP
func VerifyForgotPasswordOTP(c *gin.Context) {
	logger.InfoLogger.Info("VerifyForgotPasswordOTP called")

	var request struct {
		Email       string `json:"email" binding:"required,email"`
		OTP         string `json:"otp" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
		Username    string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	request.Email = strings.ToLower(strings.TrimSpace(request.Email))

	// Retrieve OTP hash from Redis using the password reset key
	storedHash, err := RetrieveOTP("forgot_password_otp:" + request.Username + "-" + request.Email)
	if err != nil {
		logger.ErrorLogger.Error("OTP expired or not found")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP expired or not found"})
		return
	}

	// Verify OTP
	if utils.HashOTP(request.OTP) != storedHash {
		logger.ErrorLogger.Error("Incorrect OTP")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect OTP"})
		return
	}

	// Get user
	user, err := models.GetUserByUsername(db.DB, request.Username)
	if err != nil || user.Email != request.Email {
		logger.ErrorLogger.Error("User not found or email mismatch")
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found or email mismatch"})
		return
	}

	// Hash the new password
	hashedPassword, err := models.HashPassword(request.NewPassword)
	if err != nil {
		logger.ErrorLogger.Error("Failed to hash password")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Update user's password
	_, err = db.DB.Exec(ctx, "UPDATE users SET password_hash = $1 WHERE id = $2", hashedPassword, user.ID)
	if err != nil {
		logger.ErrorLogger.Error("Failed to update password" + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	// Delete OTP from Redis
	if err := ClearOTP("forgot_password_otp:" + request.Username + "-" + request.Email); err != nil {
		logger.ErrorLogger.Warn("Failed to delete OTP after use")
	}

	logger.InfoLogger.Info("Password reset successful")

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset successful",
	})
}

// Verify Customer OTP for for account and return JWT token
func VerifyCustomerOTP(c *gin.Context) {
	logger.InfoLogger.Info("VerifyCustomerOTP called on mail")

	var request struct {
		Email string `json:"email"`
		OTP   string `json:"otp"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	if request.Email == "" || request.OTP == "" {
		logger.ErrorLogger.Error("Email and OTP are required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email and OTP are required"})
		return
	}

	// Retrieve OTP hash from Redis
	storedHash, err := RetrieveOTP("otp:" + request.Email)
	if err != nil {
		logger.ErrorLogger.Error("OTP expired or not found")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP expired or not found"})
		return
	}

	// Verify OTP
	if utils.HashOTP(request.OTP) != storedHash {
		logger.ErrorLogger.Error("Incorrect OTP")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect OTP"})
		return
	}

	// Get user by email to retrieve userID
	user, err := models.GetCustomerByEmail(db.DB, request.Email)
	if err != nil {
		logger.ErrorLogger.Errorf("User not found: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Generate access token (60 minutes)
	accessToken, err := models.GenerateAccessToken(user.ID, 60*time.Minute)
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate access token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	// Generate refresh token (7 days)
	refreshToken, err := models.GenerateRefreshToken(user.ID, 30*24*time.Hour) // Refresh Token expires in 30 days
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate refresh token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	// Delete OTP from Redis after successful verification
	if err := ClearOTP("otp:" + request.Email); err != nil {
		logger.ErrorLogger.Error("Failed to delete OTP from Redis")
	}

	// Update user's email verification and refresh token in DB
	_, err = db.DB.Exec(context.Background(),
		"UPDATE customers SET is_verified_email = true, refresh_token = $1 WHERE email = $2",
		refreshToken, request.Email)
	if err != nil {
		logger.ErrorLogger.Error("Failed to update user data")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user data"})
		return
	}

	logger.InfoLogger.Info("Email verified and tokens generated successfully")

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
	})
}

// SendCustomerOTP sends an OTP to a customer.
func SendCustomerOTP(emailAddress, otp string, templatePath string) error {
	logger.InfoLogger.Info("SendCustomerOTP called on mail")

	var user models.Customer
	query := `SELECT id, email FROM customers WHERE email = $1`

	err := db.DB.QueryRow(context.Background(), query, emailAddress).Scan(&user.ID, &user.Email)
	if err != nil {
		return err
	}

	// Store OTP using email as key for customer OTPs
	if err := StoreOTP("otp:"+emailAddress, otp); err != nil {
		return err
	}

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return err
	}

	data := struct {
		OTP  string
		Year int
	}{
		OTP:  otp,
		Year: time.Now().Year(),
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return err
	}

	smtpClient, err := newSMTPClient()
	if err != nil {
		logger.ErrorLogger.Errorf("failed to connect to SMTP server: %v", err)
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer smtpClient.Close()

	emailMsg := mail.NewMSG()
	emailMsg.SetFrom(os.Getenv("FROM_EMAIL")).
		AddTo(user.Email).
		SetSubject("Your OTP Code").
		SetBody(mail.TextHTML, body.String())

	logger.InfoLogger.Info("Sending OTP email to: ", user.Email)

	return emailMsg.Send(smtpClient)
}

// Send OTP to customer for login
func SendCustomerLoginOTP(c *gin.Context) {
	logger.InfoLogger.Info("SendCustomerLoginOTP called on mail")

	var request struct {
		Email string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	err = SendCustomerOTP(request.Email, otp, "templates/customer_otp_login.html")
	if err != nil {
		logger.ErrorLogger.Error("Failed to send OTP")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP"})
		return
	}

	logger.InfoLogger.Info("OTP send successfully")
	c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
}
