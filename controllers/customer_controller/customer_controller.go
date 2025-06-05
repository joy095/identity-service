package customer_controller

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/joy095/identity/config/db"
	redisclient "github.com/joy095/identity/config/redis" // Assuming this is your Redis client package
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/customer_models" // Assuming your customer model operations
	"github.com/joy095/identity/models/shared_models"
	"github.com/joy095/identity/utils"              // For OTP generation/hashing
	"github.com/joy095/identity/utils/mail"         // For sending emails
	"github.com/joy095/identity/utils/shared_utils" // For constants like prefixes and exp times
	"github.com/redis/go-redis/v9"                  // Correct Redis go-redis package
)

const MAX_ACTIVE_DEVICES = 5 // Define the maximum number of active devices a user can have

// CustomerController holds methods for customer-related operations
type CustomerController struct{}

// NewCustomerController creates and returns a new instance of CustomerController
func NewCustomerController() *CustomerController {
	return &CustomerController{}
}

// CustomerRegister handles user registration (OTP-based, sends OTP to email)
func (uc *CustomerController) CustomerRegister(c *gin.Context) {
	logger.InfoLogger.Info("CustomerRegister controller called")

	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("error binding JSON for registration: %w", err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if customer already exists using the models layer
	_, err := customer_models.GetCustomerByEmail(db.DB, req.Email)
	if err == nil { // This means a customer *was* found, so it's already registered
		logger.InfoLogger.Infof("Attempted to register with existing email: %s", req.Email)
		c.JSON(http.StatusConflict, gin.H{"error": "User with this email already registered. Please login or use a different email."})
		return
	}
	if err != nil && err != pgx.ErrNoRows { // A real database error occurred
		logger.ErrorLogger.Error(fmt.Errorf("database error when checking for existing user: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check user existence"})
		return
	}

	// Create a new customer via the models layer
	user, err := customer_models.CreateCustomer(db.DB, req.Email)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to create user in database: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	// Store OTP in Redis
	otpKey := shared_utils.CUSTOMER_OTP_PREFIX + strings.ToLower(strings.TrimSpace(req.Email))
	// OTP valid for 5 minutes
	if err := redisclient.GetRedisClient().Set(c.Request.Context(), otpKey, utils.HashOTP(otp), 5*time.Minute).Err(); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to store OTP in Redis: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP"})
		return
	}

	go func() {
		sendErr := mail.SendCustomerOTP(req.Email, otp, mail.CustomerVerifyEmailTemplate)
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send OTP email to %s: %w", req.Email, sendErr))
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("OTP email sent successfully to: %s", req.Email))
		}
	}()

	logger.InfoLogger.Infof("User registered successfully with ID: %v", user.ID)
	c.JSON(http.StatusCreated, gin.H{"id": user.ID, "email": user.Email, "message": "OTP sent to your email for verification."})
}

// AlreadyRegistered handles checking if a customer is already registered
func (uc *CustomerController) AlreadyRegistered(c *gin.Context) {
	logger.InfoLogger.Info("AlreadyRegistered controller called")

	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Invert the logic: IsUsernameAvailable typically means *true* if available (not taken)
	// So, if it's NOT available, the user is already registered.
	isAvailable, err := customer_models.IsUsernameAvailable(db.DB, req.Email)
	if err != nil {
		logger.ErrorLogger.Error("Database error checking Email availability: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if !isAvailable { // If not available, means it's taken
		logger.InfoLogger.Info(fmt.Sprintf("Email '%s' is not available (already registered)", req.Email))
		c.JSON(http.StatusOK, gin.H{"available": false, "message": "Email is already taken"})
	} else {
		logger.InfoLogger.Info(fmt.Sprintf("Email '%s' is available (not registered)", req.Email))
		c.JSON(http.StatusOK, gin.H{"available": true})
	}
}

// RequestCustomerLogin handles requesting an OTP for login
func (uc *CustomerController) RequestCustomerLogin(c *gin.Context) {
	logger.InfoLogger.Info("RequestCustomerLogin controller called")

	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("error binding JSON for OTP login request: %w", err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if customer exists before sending OTP to prevent email enumeration
	_, err := customer_models.GetCustomerByEmail(db.DB, req.Email)
	if err != nil {
		if err == pgx.ErrNoRows {
			logger.InfoLogger.Infof("Attempted OTP login request for non-existent email: %s", req.Email)
			// Return a generic message to prevent email enumeration
			c.JSON(http.StatusOK, gin.H{"message": "If the email exists, an OTP has been sent"})
			return
		}
		logger.ErrorLogger.Error(fmt.Errorf("database error when checking for existing user during OTP request: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process OTP request"})
		return
	}

	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	// Store OTP in Redis
	cleanEmail := strings.ToLower(strings.TrimSpace(req.Email))
	otpKey := shared_utils.CUSTOMER_OTP_PREFIX + cleanEmail
	// OTP valid for 5 minutes
	if err := redisclient.GetRedisClient().Set(c.Request.Context(), otpKey, utils.HashOTP(otp), 5*time.Minute).Err(); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to store OTP in Redis: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP"})
		return
	}

	go func() {
		sendErr := mail.SendCustomerOTP(req.Email, otp, mail.CustomerLoginTemplate)
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send OTP email to %s: %w", req.Email, sendErr))
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("OTP email sent successfully to: %s", req.Email))
		}
	}()

	c.JSON(http.StatusOK, gin.H{"message": "If the email exists, an OTP has been sent"})
}

// processCustomerEmailVerification handles both initial verification (registration) and subsequent logins
func (uc *CustomerController) processCustomerEmailVerification(c *gin.Context, email, otp, device string) {
	logger.InfoLogger.Info("processCustomerEmailVerification called")

	email = strings.ToLower(strings.TrimSpace(email))
	if device == "" {
		device = "unknown" // Default device if not provided
	}

	ctx := c.Request.Context() // Use context from gin.Context for consistency

	// --- OTP Verification ---
	storedHash, err := redisclient.GetRedisClient().Get(ctx, shared_utils.CUSTOMER_OTP_PREFIX+email).Result()
	if err != nil {
		if err == redis.Nil { // Correct way to check for "redis: nil"
			logger.ErrorLogger.Info(fmt.Sprintf("Customer OTP expired or not found for %s", email))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP expired or not found"})
			return
		}
		logger.ErrorLogger.Errorf("Failed to retrieve customer OTP from Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during OTP verification"})
		return
	}

	if utils.HashOTP(otp) != storedHash {
		logger.ErrorLogger.Info(fmt.Sprintf("Incorrect OTP for customer %s", email))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect OTP"})
		return
	}

	// --- Customer Retrieval ---
	// Ensure GetCustomerByEmail correctly retrieves the TokenVersion field
	customer, err := customer_models.GetCustomerByEmail(db.DB, email)
	if err != nil {
		logger.ErrorLogger.Errorf("Customer not found for email %s: %v", email, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Customer not found"})
		return
	}

	// --- Delete OTP from Redis after successful verification ---
	if err := redisclient.GetRedisClient().Del(ctx, shared_utils.CUSTOMER_OTP_PREFIX+email).Err(); err != nil {
		logger.ErrorLogger.Warnf("Failed to delete customer OTP from Redis for %s: %v", email, err)
		// Do not return error here, as OTP verification already succeeded
	}

	// --- TOKEN GENERATION with TokenVersion ---
	// Get the customer's current token_version from the fetched customer object.
	// When a customer is first verified, this will typically be 1 (the default).
	currentTokenVersion := customer.TokenVersion

	// Generate new access token
	accessToken, err := shared_models.GenerateAccessToken(customer.ID, currentTokenVersion, 60*time.Minute)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to generate access token for customer %s: %v", customer.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	// Generate new refresh token (this must be the pure JWT)
	refreshToken, err := shared_models.GenerateRefreshToken(customer.ID, currentTokenVersion, shared_utils.REFRESH_TOKEN_EXP_HOURS*time.Hour)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to generate refresh token for customer %s: %v", customer.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	// --- Multi-Device Refresh Token Management (using ZSET) ---
	// This approach implies you are managing multiple active refresh tokens per customer.
	// The ZSET key should ideally be `customer:{customer_id}:refresh_tokens`.
	// The member should uniquely identify the refresh token, e.g., its JTI (JWT ID) or a composite of JTI and device.
	refreshTokenZSetKey := fmt.Sprintf(shared_utils.CUSTOMER_REFRESH_TOKEN_PREFIX, customer.ID.String())

	// If you want to store the full JWT refresh token along with device for traceability:
	// IMPORTANT: You need to parse the `refreshToken` to get its JTI for robust management.
	// Let's assume you have a way to extract JTI.
	// For now, we'll store a combination of JTI and device in the ZSET member.
	// A new `jti` field has been added to `shared_models.Claims` in a previous update.
	refreshClaims, err := shared_models.ParseToken(refreshToken, func(userID uuid.UUID) (int, error) {
		customer, err := customer_models.GetCustomerByID(db.DB, userID)
		if err != nil {
			return 0, err
		}
		return customer.TokenVersion, nil
	})
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to parse newly generated refresh token for JTI: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process token"})
		return
	}
	jti := refreshClaims.RegisteredClaims.ID // Access the JTI from RegisteredClaims

	// Get current number of active sessions
	currentSessions, err := redisclient.GetRedisClient().ZCard(ctx, refreshTokenZSetKey).Result()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get session count for customer %s: %v", customer.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to manage sessions"})
		return
	}

	if currentSessions >= MAX_ACTIVE_DEVICES {
		// Remove the oldest session if limit is reached
		oldestMembers, err := redisclient.GetRedisClient().ZRange(ctx, refreshTokenZSetKey, 0, 0).Result()
		if err != nil || len(oldestMembers) == 0 {
			logger.ErrorLogger.Errorf("Failed to retrieve oldest refresh token for customer %s: %v", customer.ID, err)
			// Proceed, but log the error
		} else {
			if _, err := redisclient.GetRedisClient().ZRem(ctx, refreshTokenZSetKey, oldestMembers[0]).Result(); err != nil {
				logger.ErrorLogger.Errorf("Failed to remove oldest refresh token %s for customer %s: %v", oldestMembers[0], customer.ID, err)
			} else {
				logger.InfoLogger.Infof("Removed oldest refresh token %s for customer %s due to device limit", oldestMembers[0], customer.ID)
			}
		}
	}

	// Store refresh token's JTI and device info in Redis Sorted Set
	// The score will be the timestamp (for ordering by oldest)
	now := float64(time.Now().Unix())                  // Use Unix seconds for score
	memberToStore := fmt.Sprintf("%s:%s", jti, device) // Store JTI:device in the ZSET member

	if err := redisclient.GetRedisClient().ZAdd(ctx, refreshTokenZSetKey, redis.Z{
		Score:  now,
		Member: memberToStore, // Store the composite string here
	}).Err(); err != nil {
		logger.ErrorLogger.Errorf("Failed to store refresh token JTI/device for customer %s in Redis: %v", customer.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store refresh token"})
		return
	}

	// Set expiration for the ZSET key itself, based on the refresh token's maximum life.
	// This ensures the entire set for a customer eventually cleans up if inactive.
	if err := redisclient.GetRedisClient().Expire(ctx, refreshTokenZSetKey, shared_utils.REFRESH_TOKEN_EXP_HOURS*time.Hour).Err(); err != nil {
		logger.ErrorLogger.Warnf("Failed to set expiry for refresh token ZSET key %s: %v", refreshTokenZSetKey, err)
	}

	logger.InfoLogger.Debugf("Refresh token JTI %s stored in Redis for customer %s with ZSET key %s, member %s", jti, customer.ID, refreshTokenZSetKey, memberToStore)

	// --- Update email verification status if not already true ---
	// You might want to wrap this in a transaction if other DB operations are involved.
	if !customer.IsVerifiedEmail {
		_, err = db.DB.Exec(ctx,
			"UPDATE customers SET is_verified_email = true WHERE id = $1 AND is_verified_email = false",
			customer.ID)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to update customer email verification status for %s: %v", customer.ID, err)
			// Log the error but continue, as tokens are already generated
		} else {
			customer.IsVerifiedEmail = true // Update in-memory struct
		}
	}

	logger.InfoLogger.Infof("Customer email verified and tokens generated successfully for customer %s", customer.ID)

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": refreshToken, // Send the pure JWT refresh token back to the client
		"message":      "Customer email verified and logged in successfully!",
	})
}

// VerifyCustomerEmail (direct call)
func (uc *CustomerController) VerifyCustomerEmail(c *gin.Context) {
	logger.InfoLogger.Info("VerifyCustomerEmail (direct call) called")

	var request struct {
		Email  string `json:"email" binding:"required,email"`
		OTP    string `json:"otp" binding:"required,len=6"`
		Device string `json:"device"` // Added device field
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request for VerifyCustomerEmail: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	uc.processCustomerEmailVerification(c, request.Email, request.OTP, request.Device)
}

// CustomerLogin handles user login using Email and OTP
func (uc *CustomerController) CustomerLogin(c *gin.Context) {
	logger.InfoLogger.Info("CustomerLogin (OTP based) controller called")

	var req struct {
		Email  string `json:"email" binding:"required,email"`
		OTP    string `json:"otp" binding:"required,len=6"`
		Device string `json:"device"` // Optional, but recommended for multi-device support
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("error binding JSON for OTP login: %w", err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Pass the already bound data to the unified verification function
	uc.processCustomerEmailVerification(c, req.Email, req.OTP, req.Device)
}

// CustomerLogout handles user logout by invalidating the refresh token
// Expects "refreshToken" in the request body (pure JWT)
func (uc *CustomerController) CustomerLogout(c *gin.Context) {
	logger.InfoLogger.Info("CustomerLogout controller called")

	var req struct {
		RefreshToken string `json:"refreshToken" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid request for CustomerLogout: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	ctx := c.Request.Context()

	// Parse the refresh token to get the claims, especially UserID and JTI.
	claims, err := shared_models.ParseToken(req.RefreshToken, func(userID uuid.UUID) (int, error) {
		customer, err := customer_models.GetCustomerByID(db.DB, userID)
		if err != nil {
			return 0, err
		}
		return customer.TokenVersion, nil
	})
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to parse refresh token during logout: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or malformed refresh token"})
		return
	}

	// Ensure it's a refresh token.
	if claims.Type != "refresh" {
		logger.WarnLogger.Warnf("Attempt to use non-refresh token (%s) for logout endpoint for customer %s", claims.Type, claims.UserID)
		c.JSON(http.StatusForbidden, gin.H{"error": "Only refresh tokens are allowed for this endpoint"})
		return
	}

	customerID := claims.UserID
	jti := claims.RegisteredClaims.ID // Get the JTI (JWT ID) from the claims

	refreshTokenZSetKey := fmt.Sprintf("customer:%s:refresh_tokens", customerID.String())

	// Use ZScan with the JTI as a prefix to find the specific refresh token(s) to remove.
	// Since your stored members are `jti:device`, matching `jti:*` will find the correct entry.
	membersToRemove := []interface{}{}
	cursor := uint64(0)
	matchPattern := jti + ":*" // Search for any member starting with this JTI

	// Iterate through the ZSET to find and collect all matching members.
	// It's possible (though unlikely if single-use is enforced) that multiple entries
	// exist for the same JTI if there were prior logic issues. This ensures all are cleaned.
	for {
		var keys []string
		var scanErr error
		keys, cursor, scanErr = redisclient.GetRedisClient().ZScan(ctx, refreshTokenZSetKey, cursor, matchPattern, 100).Result() // Scan in batches
		if scanErr != nil {
			logger.ErrorLogger.Errorf("Failed to scan for refresh token to remove for customer %s (JTI: %s): %v", customerID, jti, scanErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
			return
		}

		if len(keys) > 0 {
			// Convert the slice of strings to a slice of interfaces for ZRem.
			for _, key := range keys {
				membersToRemove = append(membersToRemove, key)
			}
		}

		if cursor == 0 { // No more elements to scan
			break
		}
	}

	if len(membersToRemove) == 0 {
		logger.InfoLogger.Infof("Refresh token (JTI: %s) not found in Redis for customer %s, already logged out or invalid.", jti, customerID)
		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully (token not found or already invalid)"})
		return
	}

	// Perform the removal of all collected matching members.
	if _, err := redisclient.GetRedisClient().ZRem(ctx, refreshTokenZSetKey, membersToRemove...).Result(); err != nil {
		logger.ErrorLogger.Errorf("Failed to remove refresh token(s) (JTI: %s) for customer %s from Redis: %v", jti, customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}

	logger.InfoLogger.Infof("Customer %s logged out successfully. %d refresh token(s) (JTI: %s) invalidated.", customerID, len(membersToRemove), jti)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// CustomerRefreshToken handles refreshing access tokens using a refresh token
// Expects "Refresh-Token: Bearer <JWT_REFRESH_TOKEN>" in the header
func (uc *CustomerController) CustomerRefreshToken(c *gin.Context) {
	logger.InfoLogger.Info("CustomerRefreshToken controller called")

	// 1. Get and validate the Refresh-Token header
	refreshHeader := c.GetHeader("Refresh-Token")
	if refreshHeader == "" {
		logger.ErrorLogger.Error("Refresh-Token header missing.")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh-Token header missing"})
		return
	}

	if !strings.HasPrefix(refreshHeader, "Bearer ") {
		logger.ErrorLogger.Error("Invalid Refresh-Token header format.")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Refresh-Token header format (expected 'Bearer ' prefix)"})
		return
	}
	refreshTokenFromHeader := strings.TrimPrefix(refreshHeader, "Bearer ")

	if refreshTokenFromHeader == "" {
		logger.ErrorLogger.Error("Refresh token is empty after stripping Bearer prefix.")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token is empty"})
		return
	}

	ctx := c.Request.Context()

	// 2. Parse and validate the incoming refresh token.
	// This step verifies the signature, expiry, and extracts the claims (UserID, JTI, TokenVersion, Type).
	claims, err := shared_models.ParseToken(refreshTokenFromHeader, func(userID uuid.UUID) (int, error) {
		customer, err := customer_models.GetCustomerByID(db.DB, userID)
		if err != nil {
			return 0, err
		}
		return customer.TokenVersion, nil
	})
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to parse or validate refresh token: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		return
	}

	// 3. Ensure the token is actually a refresh token.
	if claims.Type != "refresh" {
		logger.WarnLogger.Warnf("Attempt to use non-refresh token (%s) for refresh endpoint for customer %s.", claims.Type, claims.UserID)
		c.JSON(http.StatusForbidden, gin.H{"error": "Only refresh tokens are allowed for this endpoint"})
		return
	}

	customerID := claims.UserID
	jti := claims.RegisteredClaims.ID // Get the JTI from the incoming token's claims

	// 4. Retrieve the customer from the database to get their *current* token_version.
	customer, err := customer_models.GetCustomerByID(db.DB, customerID)
	if err != nil {
		if err == pgx.ErrNoRows {
			logger.ErrorLogger.Errorf("Customer %s not found for refresh token: %v.", customerID, err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User associated with token not found or already deleted"})
		} else {
			logger.ErrorLogger.Errorf("Database error fetching customer %s for refresh token: %v.", customerID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error during token refresh"})
		}
		return
	}
	if customer == nil { // A sanity check, though pgx.ErrNoRows should handle this
		logger.ErrorLogger.Errorf("Customer %s unexpectedly nil for refresh token.", customerID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User associated with token not found"})
		return
	}

	// 5. CRITICAL: Token Version Check for Revocation.
	// If the token's version is less than the current version in the database, it's revoked.
	if claims.TokenVersion < customer.TokenVersion {
		logger.WarnLogger.Warnf("Refresh token for customer %s (v%d) is outdated. Current DB version: v%d. Token revoked.", customerID, claims.TokenVersion, customer.TokenVersion)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Your session has been revoked. Please log in again."})
		return
	}

	refreshTokenZSetKey := fmt.Sprintf("customer:%s:refresh_tokens", customerID.String())

	// 6. Verify Refresh Token's Presence and Uniqueness in Redis (using JTI).
	// We search for a member in the ZSET that starts with the incoming token's JTI.
	var actualMemberInRedis string // This will store the full "jti:device" string found in Redis
	found := false

	// Use ZScan to iterate and find the member that matches the JTI (e.g., "jti:device_name").
	// Using a pattern like `jti+":"` ensures we target the correct format.
	iter := redisclient.GetRedisClient().ZScan(ctx, refreshTokenZSetKey, 0, jti+":*", 0).Iterator()
	for iter.Next(ctx) {
		memberStr := iter.Val()
		parts := strings.SplitN(memberStr, ":", 2)
		if len(parts) > 0 && parts[0] == jti { // Check if the JTI part matches exactly
			actualMemberInRedis = memberStr
			found = true
			break // Found the specific token's entry, no need to scan further
		}
	}
	if err := iter.Err(); err != nil {
		logger.ErrorLogger.Errorf("Failed to scan for refresh token during refresh for customer %s (JTI: %s): %v.", customerID, jti, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh token"})
		return
	}

	if !found {
		logger.ErrorLogger.Infof("Refresh token (JTI: %s) not found in Redis for customer %s or already revoked/used.", jti, customerID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or revoked refresh token"})
		return
	}

	// 7. Invalidate the old refresh token (single-use refresh token rotation).
	// Remove the *exact composite member* found in Redis using `actualMemberInRedis`.
	if _, err := redisclient.GetRedisClient().ZRem(ctx, refreshTokenZSetKey, actualMemberInRedis).Result(); err != nil {
		logger.ErrorLogger.Warnf("Failed to remove used refresh token %s for customer %s (JTI: %s): %v.", actualMemberInRedis, customerID, jti, err)
		// Don't fail the request, but log the warning as it's a cleanup task.
	}

	// 8. Generate new Access Token.
	// Use the *customer's current TokenVersion* from the database to issue new tokens.
	newAccessToken, err := shared_models.GenerateAccessToken(customerID, customer.TokenVersion, 60*time.Minute)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to generate new access token during refresh for customer %s: %v.", customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate new access token"})
		return
	}

	// 9. Generate new Refresh Token.
	newRefreshToken, err := shared_models.GenerateRefreshToken(customerID, customer.TokenVersion, shared_utils.REFRESH_TOKEN_EXP_HOURS*time.Hour)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to generate new refresh token during refresh for customer %s: %v.", customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate new refresh token"})
		return
	}

	// 10. Extract device from the *actualMemberInRedis* string.
	// This ensures the new token is associated with the same device as the old one.
	device := "unknown_device"
	var parts []string
	parts = strings.SplitN(actualMemberInRedis, ":", 2) // Reuse parts from previous split, or re-split if needed
	if len(parts) == 2 {
		device = parts[1] // The second part should be the device name
	} else {
		logger.WarnLogger.Warnf("Could not extract device from Redis member: %s. Defaulting to '%s'. This indicates a previous storage issue.", actualMemberInRedis, device)
	}

	// 11. Store the new refresh token's JTI and device info in Redis Sorted Set.
	newRefreshClaims, err := shared_models.ParseToken(newRefreshToken, func(userID uuid.UUID) (int, error) {
		customer, err := customer_models.GetCustomerByID(db.DB, userID)
		if err != nil {
			return 0, err
		}
		return customer.TokenVersion, nil
	})
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to parse newly generated refresh token for JTI (post-refresh): %v.", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process new token"})
		return
	}
	newJTI := newRefreshClaims.RegisteredClaims.ID

	now := float64(time.Now().Unix())                 // Use Unix seconds for score
	newMember := fmt.Sprintf("%s:%s", newJTI, device) // Use the new JTI and derived device

	logger.DebugLogger.Debugf("DEBUG_CONTROLLER: Storing new Redis member: %s for customer %s (New JTI: %s).", newMember, customerID, newJTI)

	if err := redisclient.GetRedisClient().ZAdd(ctx, refreshTokenZSetKey, redis.Z{
		Score:  now,
		Member: newMember,
	}).Err(); err != nil {
		logger.ErrorLogger.Errorf("Failed to store new refresh token JTI/device for customer %s in Redis: %v.", customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store new refresh token"})
		return
	}

	// 12. Update expiry for the ZSET key (ensures the entire set of refresh tokens expires if idle).
	if err := redisclient.GetRedisClient().Expire(ctx, refreshTokenZSetKey, shared_utils.REFRESH_TOKEN_EXP_HOURS*time.Hour).Err(); err != nil {
		logger.ErrorLogger.Warnf("Failed to update expiry for refresh token key %s after refresh: %v.", refreshTokenZSetKey, err)
	}

	logger.InfoLogger.Infof("Access token refreshed successfully for customer %s. New refresh token (JTI: %s) issued.", customerID, newJTI)
	c.JSON(http.StatusOK, gin.H{
		"accessToken":  newAccessToken,
		"refreshToken": newRefreshToken,
		"message":      "Tokens refreshed successfully!",
	})
}
