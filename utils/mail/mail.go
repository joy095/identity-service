package mail

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joy095/identity/config"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/models"
	"github.com/joy095/identity/utils"

	"github.com/joy095/identity/logger"

	"github.com/gin-gonic/gin"
	redisclient "github.com/joy095/identity/config/redis"
	mail "github.com/xhit/go-simple-mail/v2"
)

// var smtpClient *mail.SMTPClient

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

// Hash OTP using Argon2 for security

// Store OTP hash in Redis with expiration
func StoreOTP(email, otp string) error {
	hashedOTP := utils.HashOTP(otp)
	return redisclient.GetRedisClient().Set(context.Background(), "otp:"+email, hashedOTP, 10*time.Minute).Err()
}

// continue OTP hash comparison...
func SendOTP(emailAddress, firstName, lastName, otp string) error {
	logger.InfoLogger.Info("SendOTP called on mail")

	var user models.Customer
	query := `SELECT id, email FROM users WHERE email = $1`

	// query := `SELECT id FROM users WHERE id = $1`
	err := db.DB.QueryRow(context.Background(), query, emailAddress).Scan(&user.ID, &user.Email)
	if err != nil {
		return err
	}

	// Store OTP before sending email
	if err := StoreOTP(emailAddress, otp); err != nil {
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

	// Create a new SMTP client for each email
	smtpClient, err := newSMTPClient()
	if err != nil {
		logger.ErrorLogger.Errorf("failed to connect to SMTP server: %v", err)
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer smtpClient.Close()

	email := mail.NewMSG()
	email.SetFrom(os.Getenv("FROM_EMAIL")).
		AddTo(user.Email).
		SetSubject("Your OTP Code").
		SetBody(mail.TextHTML, body.String())

	logger.InfoLogger.Info("Sending OTP email to: ", user.Email)

	return email.Send(smtpClient)
}

// SendOTP sends an OTP to the provided email address
func SendForgotPasswordOTP(emailAddress, otp string) error {
	logger.InfoLogger.Info("SendForgotPasswordOTP called on mail")

	var user models.User
	query := `SELECT id, email FROM users WHERE email = $1`
	err := db.DB.QueryRow(context.Background(), query, emailAddress).Scan(&user.ID, &user.Email)
	if err != nil {
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

	email := mail.NewMSG()
	email.SetFrom(os.Getenv("FROM_EMAIL")).
		AddTo(user.Email).
		SetSubject("Reset Your Password - OTP").
		SetBody(mail.TextHTML, body.String())

	logger.InfoLogger.Infof("Sending password reset OTP email to: %s", user.Email)

	return email.Send(smtpClient)
}

// Request OTP API
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

	err = StoreOTP(request.Email, otp)
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

// Verify OTP and return JWT token
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

	// Retrieve OTP hash from Redis
	storedHash, err := redisclient.GetRedisClient().Get(ctx, "otp:"+request.Email).Result()
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

	// Store refresh token in Redis
	// err = redisclient.GetRedisClient().Set(ctx, "refresh:"+request.Email, refreshToken, 7*24*time.Hour).Err()
	// if err != nil {
	// 	logger.ErrorLogger.Error("Failed to store refresh token")
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store refresh token"})
	// 	return
	// }

	// Delete OTP from Redis after successful verification
	if err := redisclient.GetRedisClient().Del(ctx, "otp:"+request.Email).Err(); err != nil {
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

	// Retrieve OTP hash from Redis
	storedHash, err := redisclient.GetRedisClient().Get(ctx, "otp:"+request.Username+"-"+request.Email).Result()
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
	if err := redisclient.GetRedisClient().Del(ctx, "otp:"+request.Username+"-"+request.Email).Err(); err != nil {
		logger.ErrorLogger.Warn("Failed to delete OTP after use")
	}

	logger.InfoLogger.Info("Password reset successful")

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset successful",
	})
}

// SendOTPCustomer
// func SendOTPCustomer(emailAddress, otp string) error {
// 	logger.InfoLogger.Info("SendOTP called on mail")

// 	var user models.Customer
// 	query := `SELECT id, email FROM customers WHERE email = $1`

// 	// query := `SELECT id FROM users WHERE id = $1`
// 	err := db.DB.QueryRow(context.Background(), query, emailAddress).Scan(&user.ID, &user.Email)
// 	if err != nil {
// 		return err
// 	}

// 	// Store OTP before sending email
// 	if err := StoreOTP(emailAddress, otp); err != nil {
// 		return err
// 	}

// 	tmpl, err := template.ParseFiles("templates/customer_otp.html")
// 	if err != nil {
// 		return err
// 	}

// 	var body bytes.Buffer
// 	data := struct {
// 		OTP  string
// 		Year int
// 	}{
// 		OTP:  otp,
// 		Year: time.Now().Year(),
// 	}

// 	if err := tmpl.Execute(&body, data); err != nil {
// 		return err
// 	}

// 	// Create a new SMTP client for each email
// 	smtpClient, err := newSMTPClient()
// 	if err != nil {
// 		logger.ErrorLogger.Errorf("failed to connect to SMTP server: %v", err)
// 		return fmt.Errorf("failed to connect to SMTP server: %w", err)
// 	}
// 	defer smtpClient.Close()

// 	email := mail.NewMSG()
// 	email.SetFrom(os.Getenv("FROM_EMAIL")).
// 		AddTo(user.Email).
// 		SetSubject("Your OTP Code").
// 		SetBody(mail.TextHTML, body.String())

// 	logger.InfoLogger.Info("Sending OTP email to: ", user.Email)

// 	return email.Send(smtpClient)
// }

// Verify Customer OTP for for account and return JWT token
func VerifyCustomerOTP(c *gin.Context) {
	logger.InfoLogger.Info("VerifyOTP called on mail")

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
	storedHash, err := redisclient.GetRedisClient().Get(ctx, "otp:"+request.Email).Result()
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

	// Store refresh token in Redis
	// err = redisclient.GetRedisClient().Set(ctx, "refresh:"+request.Email, refreshToken, 7*24*time.Hour).Err()
	// if err != nil {
	// 	logger.ErrorLogger.Error("Failed to store refresh token")
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store refresh token"})
	// 	return
	// }

	// Delete OTP from Redis after successful verification
	if err := redisclient.GetRedisClient().Del(ctx, "otp:"+request.Email).Err(); err != nil {
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

// continue OTP hash comparison...
func SendCustomerOTP(emailAddress, otp string, templatePath string) error {
	logger.InfoLogger.Info("SendOTP called on mail")

	var user models.Customer
	query := `SELECT id, email FROM customers WHERE email = $1`

	err := db.DB.QueryRow(context.Background(), query, emailAddress).Scan(&user.ID, &user.Email)
	if err != nil {
		return err
	}

	// Store OTP before sending email
	if err := StoreOTP(emailAddress, otp); err != nil {
		return err
	}

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return err
	}

	// Rest of function remains the same
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

	// Create a new SMTP client for each email
	smtpClient, err := newSMTPClient()
	if err != nil {
		logger.ErrorLogger.Errorf("failed to connect to SMTP server: %v", err)
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer smtpClient.Close()

	email := mail.NewMSG()
	email.SetFrom(os.Getenv("FROM_EMAIL")).
		AddTo(user.Email).
		SetSubject("Your OTP Code").
		SetBody(mail.TextHTML, body.String())

	logger.InfoLogger.Info("Sending OTP email to: ", user.Email)

	return email.Send(smtpClient)
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

	otp, err := utils.GenerateSecureOTP() // Assuming this generates a random string and potentially stores it securely
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
