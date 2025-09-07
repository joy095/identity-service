package business_payment_controller

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/payment_models"
	"github.com/joy095/identity/models/service_models"
	"github.com/joy095/identity/models/user_models"
	"github.com/joy095/identity/utils"
)

// Refund status constants
const (
	StatusRefundPending  = "pending"
	StatusRefundSuccess  = "success"
	StatusRefundFailed   = "failed"
	StatusRefundReversed = "reversed"
)

// Order status constants
const (
	OrderStatusPending  = "pending"
	OrderStatusPaid     = "paid"
	OrderStatusRefunded = "refunded"
)

// PaymentController handles all payment operations
type PaymentController struct {
	DB            *pgxpool.Pool
	ClientID      string
	ClientSecret  string
	APIVersion    string
	BaseURL       string
	WebhookSecret string
	HttpClient    *http.Client // Shared HTTP client for performance
}

// NewPaymentController creates a new payment controller
func NewPaymentController(db *pgxpool.Pool) (*PaymentController, error) {
	clientID := os.Getenv("CASHFREE_CLIENT_ID")
	clientSecret := os.Getenv("CASHFREE_CLIENT_SECRET")
	apiVersion := os.Getenv("CASHFREE_API_VERSION")
	webhookSecret := os.Getenv("CASHFREE_WEBHOOK_SECRET")

	if clientID == "" || clientSecret == "" || apiVersion == "" || webhookSecret == "" {
		return nil, fmt.Errorf("required Cashfree environment variables not set")
	}

	baseURL := os.Getenv("CASHFREE_BASE_URL")
	if baseURL == "" {
		baseURL = "https://sandbox.cashfree.com/pg" // Default to sandbox
	}

	pc := &PaymentController{
		DB:            db,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		APIVersion:    apiVersion,
		BaseURL:       baseURL,
		WebhookSecret: webhookSecret,
		HttpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}

	if err := pc.ValidateConfig(); err != nil {
		return nil, err
	}

	logger.InfoLogger.Infof("Webhook secret configured with length: %d", len(webhookSecret))

	return pc, nil
}

// ValidateConfig validates the payment controller configuration
func (pc *PaymentController) ValidateConfig() error {
	if pc.ClientID == "" {
		return fmt.Errorf("CASHFREE_CLIENT_ID is required")
	}
	if pc.ClientSecret == "" {
		return fmt.Errorf("CASHFREE_CLIENT_SECRET is required")
	}
	if pc.APIVersion == "" {
		return fmt.Errorf("CASHFREE_API_VERSION is required")
	}
	if pc.WebhookSecret == "" {
		return fmt.Errorf("CASHFREE_WEBHOOK_SECRET is required")
	}
	return nil
}

// HTTP client helper
func (pc *PaymentController) makeRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, pc.BaseURL+path, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("x-client-id", pc.ClientID)
	req.Header.Set("x-client-secret", pc.ClientSecret)
	req.Header.Set("x-api-version", pc.APIVersion)

	return pc.HttpClient.Do(req)
}

// verifyWebhookSignature verifies the webhook signature with enhanced debugging
func (pc *PaymentController) verifyWebhookSignature(c *gin.Context, bodyBytes []byte) bool {
	timestamp := c.GetHeader("x-webhook-timestamp")
	signature := c.GetHeader("x-webhook-signature")

	// Log received headers for debugging
	fmt.Printf("Webhook headers - timestamp present: %v, signature present: %v",
		timestamp != "", signature != "")

	if timestamp == "" || signature == "" {
		fmt.Errorf("Missing webhook headers - timestamp: %v, signature: %v",
			timestamp != "", signature != "")
		return false
	}

	// Validate timestamp format and age
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		fmt.Errorf("Invalid timestamp format: %s, error: %v", timestamp, err)
		return false
	}

	timestampTime := time.Unix(ts, 0)
	timeDiff := time.Since(timestampTime)

	// Allow 5 minutes window, reject future timestamps
	if timeDiff > 5*time.Minute || timeDiff < -time.Minute {
		fmt.Errorf("Invalid timestamp age: %v (timestamp: %s)",
			timeDiff, timestampTime.Format(time.RFC3339))
		return false
	}

	// Generate expected signature
	message := timestamp + "." + string(bodyBytes)
	mac := hmac.New(sha256.New, []byte(pc.WebhookSecret))
	mac.Write([]byte(message))
	expectedSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Enhanced debugging - log signature details (be careful in production)
	fmt.Printf("Signature verification details:")
	fmt.Printf("- Timestamp: %s", timestamp)
	fmt.Printf("- Message length: %d bytes", len(message))
	fmt.Printf("- Secret length: %d chars", len(pc.WebhookSecret))
	fmt.Printf("- Expected signature: %s", expectedSignature)
	fmt.Printf("- Received signature: %s", signature)

	// Log first few chars of signatures for comparison (safe for production)
	if len(expectedSignature) > 10 && len(signature) > 10 {
		fmt.Printf("Signature comparison - Expected starts with: %s..., Received starts with: %s...",
			expectedSignature[:10], signature[:10])
	}

	// Secure comparison
	isValid := hmac.Equal([]byte(expectedSignature), []byte(signature))

	if !isValid {
		fmt.Errorf("Webhook signature verification failed")
		fmt.Errorf("Expected signature length: %d, Received: %d",
			len(expectedSignature), len(signature))

		// Additional debug: check if signatures are similar but not exact
		if expectedSignature == signature {
			fmt.Errorf("Signatures match as strings but HMAC.Equal failed - possible encoding issue")
		}
	} else {
		fmt.Print("Webhook signature verified successfully")
	}

	return isValid
}

// Test endpoint to validate webhook secret configuration
func (pc *PaymentController) TestWebhookSecret(c *gin.Context) {
	// Test with the exact same data format as your failing webhook
	testTimestamp := "1757255424"
	testBody := `{"data":{"test_object":{"test_key":"test_value"}},"type":"WEBHOOK","event_time":"2025-09-07T14:30:23.000Z"}`

	// Generate signature using your webhook secret
	message := testTimestamp + "." + testBody
	mac := hmac.New(sha256.New, []byte(pc.WebhookSecret))
	mac.Write([]byte(message))
	generatedSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Test alternative formats
	altMessage := testTimestamp + testBody // No dot
	mac2 := hmac.New(sha256.New, []byte(pc.WebhookSecret))
	mac2.Write([]byte(altMessage))
	altSignature := base64.StdEncoding.EncodeToString(mac2.Sum(nil))

	// Hex format
	mac3 := hmac.New(sha256.New, []byte(pc.WebhookSecret))
	mac3.Write([]byte(message))
	hexSignature := fmt.Sprintf("%x", mac3.Sum(nil))

	response := gin.H{
		"webhook_secret_configured": pc.WebhookSecret != "",
		"secret_length":             len(pc.WebhookSecret),
		"test_data": gin.H{
			"timestamp": testTimestamp,
			"body":      testBody,
			"message":   message,
		},
		"signatures": gin.H{
			"standard_format":    generatedSignature,
			"no_dot_format":      altSignature,
			"hex_format":         hexSignature,
			"received_signature": "c4Ig8a7Z4zprGeCWw/bymghwRVln6tVzbEa/gQKsMfw=",
		},
		"matches": gin.H{
			"standard": generatedSignature == "c4Ig8a7Z4zprGeCWw/bymghwRVln6tVzbEa/gQKsMfw=",
			"no_dot":   altSignature == "c4Ig8a7Z4zprGeCWw/bymghwRVln6tVzbEa/gQKsMfw=",
			"hex":      hexSignature == "c4Ig8a7Z4zprGeCWw/bymghwRVln6tVzbEa/gQKsMfw=",
		},
		"debug_info": gin.H{
			"message_length": len(message),
			"body_length":    len(testBody),
		},
		"troubleshooting": gin.H{
			"step_1": "Check if webhook secret in env matches Cashfree dashboard",
			"step_2": "Verify webhook URL is correctly configured in Cashfree",
			"step_3": "Ensure webhook secret has no extra spaces or special characters",
			"step_4": "Check if you're using sandbox vs production endpoints",
		},
	}

	c.JSON(http.StatusOK, response)
}

// Additional debugging endpoint to test webhook with custom data
func (pc *PaymentController) TestCustomWebhook(c *gin.Context) {
	var req struct {
		Timestamp string `json:"timestamp" binding:"required"`
		Body      string `json:"body" binding:"required"`
		Signature string `json:"signature" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Test signature generation with custom data
	message := req.Timestamp + "." + req.Body
	mac := hmac.New(sha256.New, []byte(pc.WebhookSecret))
	mac.Write([]byte(message))
	expectedSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	isValid := hmac.Equal([]byte(expectedSignature), []byte(req.Signature))

	c.JSON(http.StatusOK, gin.H{
		"message":            message,
		"expected_signature": expectedSignature,
		"received_signature": req.Signature,
		"signature_valid":    isValid,
		"webhook_secret_len": len(pc.WebhookSecret),
	})
}

// isEventProcessed checks if the webhook event has already been processed
func (pc *PaymentController) isEventProcessed(ctx context.Context, eventType, orderID string, eventTime string) (bool, error) {
	var count int
	err := pc.DB.QueryRow(ctx,
		`SELECT COUNT(*) FROM webhook_events 
         WHERE event_type = $1 AND raw_payload::json->>'data'->>'order'->>'order_id' = $2 
         AND event_time = $3 AND processed = true`,
		eventType, orderID, eventTime).Scan(&count)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to check if event processed: %v", err)
	}

	return count > 0, err
}

// PaymentWebhook handles incoming Cashfree webhooks
func (pc *PaymentController) PaymentWebhook(c *gin.Context) {
	// Log all headers for debugging
	fmt.Printf("Webhook request received from IP: %s", c.ClientIP())
	fmt.Printf("Webhook headers: x-webhook-timestamp=%s, x-webhook-signature=%s",
		c.GetHeader("x-webhook-timestamp"),
		c.GetHeader("x-webhook-signature"))

	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		fmt.Errorf("Failed to read webhook body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	// Log body details (be careful with sensitive data in production)
	fmt.Printf("Webhook body size: %d bytes", len(bodyBytes))
	if len(bodyBytes) > 0 {
		// Log first 100 chars of body for debugging
		bodyPreview := string(bodyBytes)
		if len(bodyPreview) > 100 {
			bodyPreview = bodyPreview[:100] + "..."
		}
		fmt.Printf("Webhook body preview: %s", bodyPreview)
	}

	// Restore body for potential further processing
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Verify signature with enhanced logging
	if !pc.verifyWebhookSignature(c, bodyBytes) {
		fmt.Errorf("Invalid webhook signature for request from IP: %s", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid signature"})
		return
	}

	// Rest of your webhook processing...
	// Parse event
	var event WebhookEvent
	if err := json.Unmarshal(bodyBytes, &event); err != nil {
		fmt.Errorf("Invalid webhook payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	fmt.Printf("Successfully verified webhook: type=%s, time=%s", event.Type, event.EventTime)

	ctx := c.Request.Context()

	// Extract orderID for deduplication
	orderID := ""
	var orderData map[string]interface{}
	if err := json.Unmarshal(event.Data, &orderData); err == nil {
		if order, ok := orderData["order"].(map[string]interface{}); ok {
			if id, ok := order["order_id"].(string); ok {
				orderID = id
				processed, err := pc.isEventProcessed(ctx, event.Type, orderID, event.EventTime)
				if err == nil && processed {
					fmt.Printf("Duplicate webhook event ignored: %s for order %s", event.Type, orderID)
					c.JSON(http.StatusOK, gin.H{"status": "duplicate_ignored"})
					return
				}
			}
		}
	}

	// Log event
	var eventID int64
	err = pc.DB.QueryRow(ctx,
		`INSERT INTO webhook_events (event_type, raw_payload, processed, event_time) 
         VALUES ($1, $2, $3, $4) RETURNING id`,
		event.Type, string(bodyBytes), false, event.EventTime).Scan(&eventID)

	if err != nil {
		fmt.Errorf("Failed to log webhook event: %v", err)
		// Continue processing even if logging fails
	}

	// Route event
	switch event.Type {
	case "PAYMENT_SUCCESS_WEBHOOK":
		pc.handlePaymentSuccess(ctx, event.Data)
	case "REFUND_STATUS_WEBHOOK", "AUTO_REFUND_STATUS_WEBHOOK":
		pc.handleRefundWebhook(ctx, event.Data, event.Type)
	default:
		logger.InfoLogger.Infof("Unhandled webhook event type received: %s", event.Type)
	}

	// Mark as processed
	if eventID > 0 {
		_, err = pc.DB.Exec(ctx,
			`UPDATE webhook_events SET processed = true WHERE id = $1`, eventID)
		if err != nil {
			fmt.Errorf("Failed to update webhook event as processed: %v", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "processed"})
}

// handlePaymentSuccess processes payment success webhooks
func (pc *PaymentController) handlePaymentSuccess(ctx context.Context, data json.RawMessage) {
	var webhookData PaymentWebhookData
	if err := json.Unmarshal(data, &webhookData); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse payment success data: %v", err)
		return
	}

	orderID := webhookData.Order.OrderID
	payment := webhookData.Payment

	if orderID == "" || payment.CfPaymentID == 0 {
		logger.ErrorLogger.Errorf("Missing required fields in payment webhook: orderID=%s, paymentID=%d",
			orderID, payment.CfPaymentID)
		return
	}

	logger.InfoLogger.Infof("Processing payment success for order: %s, payment_id: %d",
		orderID, payment.CfPaymentID)

	tx, err := pc.DB.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_BEGIN_FAIL] PaymentSuccess for %s: %v", orderID, err)
		return
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && err != pgx.ErrTxClosed {
			logger.ErrorLogger.Errorf("Failed to rollback transaction for order %s: %v", orderID, err)
		}
	}()

	paymentMethodJSON, err := json.Marshal(payment.PaymentMethod)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to marshal payment method for order %s: %v", orderID, err)
		return
	}

	result, err := tx.Exec(ctx,
		`UPDATE orders 
         SET cf_payment_id = $1, payment_method = $2, bank_reference = $3, status = $4, updated_at = NOW()
         WHERE order_id = $5 AND status = $6`,
		payment.CfPaymentID, paymentMethodJSON, payment.BankReference, OrderStatusPaid, orderID, OrderStatusPending)

	if err != nil {
		logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update order for success failed for %s: %v", orderID, err)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		logger.ErrorLogger.Errorf("No pending order found with order_id: %s (possible duplicate webhook)", orderID)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("[TX_COMMIT_FAIL] PaymentSuccess for %s: %v", orderID, err)
		return
	}

	logger.InfoLogger.Infof("✅ Payment success processed for order: %s (rows updated: %d)",
		orderID, rowsAffected)
}

// handleRefundWebhook processes refund-related webhooks
func (pc *PaymentController) handleRefundWebhook(ctx context.Context, data json.RawMessage, eventType string) {
	var webhookData RefundWebhookData
	if err := json.Unmarshal(data, &webhookData); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse refund data: %v", err)
		return
	}

	refund := webhookData.Refund
	orderID := webhookData.Order.OrderID
	refundID := refund.RefundID

	if refundID == "" || orderID == "" {
		logger.ErrorLogger.Errorf("Missing required fields in refund webhook: refundID=%s, orderID=%s",
			refundID, orderID)
		return
	}

	logger.InfoLogger.Infof("Processing refund webhook type=%s status=%s for refund_id: %s, order: %s",
		eventType, refund.RefundStatus, refundID, orderID)

	tx, err := pc.DB.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_BEGIN_FAIL] Refund for %s: %v", refundID, err)
		return
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && err != pgx.ErrTxClosed {
			logger.ErrorLogger.Errorf("Failed to rollback transaction for refund %s: %v", refundID, err)
		}
	}()

	var newRefundStatus string
	var updateOrder bool
	switch refund.RefundStatus {
	case "SUCCESS":
		newRefundStatus = StatusRefundSuccess
		updateOrder = true
	case "FAILED":
		newRefundStatus = StatusRefundFailed
		updateOrder = false
	case "CANCELLED":
		newRefundStatus = StatusRefundReversed // Mapping cancelled to reversed as per original code
		updateOrder = false
	default:
		logger.InfoLogger.Infof("Unhandled refund status: %s for refund_id: %s", refund.RefundStatus, refundID)
		return
	}

	// Update refund
	result, err := tx.Exec(ctx,
		`UPDATE refunds 
         SET status = $1, cf_refund_id = $2, processed_at = $3, updated_at = NOW()
         WHERE refund_id = $4`,
		newRefundStatus, refund.CfRefundID, refund.ProcessedAt, refundID)

	if err != nil {
		logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update refund failed for %s: %v", refundID, err)
		return
	}

	refundRowsAffected := result.RowsAffected()
	if refundRowsAffected == 0 {
		logger.ErrorLogger.Errorf("No refund found with refund_id: %s", refundID)
		return
	}

	var orderRowsAffected int64
	if updateOrder {
		// Update order status to refunded only on success
		result, err = tx.Exec(ctx,
			`UPDATE orders 
             SET status = $1, updated_at = NOW()
             WHERE order_id = $2 AND status = $3`,
			OrderStatusRefunded, orderID, OrderStatusPaid)

		if err != nil {
			logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update order for refund failed for %s: %v", orderID, err)
			return
		}

		orderRowsAffected = result.RowsAffected()
		if orderRowsAffected == 0 {
			logger.ErrorLogger.Errorf("No paid order found for refund success: %s", orderID)
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("[TX_COMMIT_FAIL] Refund for %s: %v", refundID, err)
		return
	}

	logger.InfoLogger.Infof("✅ Refund %s processed for refund_id: %s (refund rows: %d, order rows: %d)",
		newRefundStatus, refundID, refundRowsAffected, orderRowsAffected)
}

// CreateOrder creates a new payment order and optionally initiates payment
func (pc *PaymentController) CreateOrder(c *gin.Context) {
	customerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		if err.Error() == "unauthorized" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	ctx := c.Request.Context()

	user, err := user_models.GetUserByID(ctx, pc.DB, customerID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get user %s: %v", customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user"})
		return
	}

	if user.Phone == nil || *user.Phone == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user phone required"})
		return
	}

	var req CreateOrderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if req.StartTime.After(req.EndTime) || req.StartTime.Equal(req.EndTime) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Start time must be before end time"})
		return
	}

	now := time.Now().UTC()
	if req.StartTime.Before(now) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Slot date/time cannot be in the past"})
		return
	}

	hasOverlap, err := payment_models.HasBookingOverlap(ctx, pc.DB, req.ServiceID, req.StartTime, req.EndTime)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to check overlap for service %s: %v", req.ServiceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check availability"})
		return
	}
	if hasOverlap {
		c.JSON(http.StatusConflict, gin.H{"error": "This time slot is already booked by another user"})
		return
	}

	if req.UpiID != "" && len(req.PaymentMethod) == 0 {
		upiRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.\-_]*[a-zA-Z0-9])?@[a-zA-Z0-9][a-zA-Z0-9]*$`)
		if !upiRegex.MatchString(req.UpiID) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid UPI ID"})
			return
		}
		req.PaymentMethod = map[string]interface{}{
			"upi": map[string]string{
				"channel": "collect",
				"upi_id":  req.UpiID,
			},
		}
	}

	service, err := service_models.GetServiceByIDModel(ctx, pc.DB, req.ServiceID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get service %s: %v", req.ServiceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get service"})
		return
	}

	payload := map[string]interface{}{
		"order_amount":   service.Price,
		"order_currency": req.Currency,
		"customer_details": map[string]string{
			"customer_id":    customerID.String(),
			"customer_phone": *user.Phone,
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to marshal order payload: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to prepare order"})
		return
	}

	resp, err := pc.makeRequest(ctx, "POST", "/orders", bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.ErrorLogger.Errorf("Cashfree request failed: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "payment gateway error"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.ErrorLogger.Errorf("Cashfree error [%d]: %s", resp.StatusCode, string(body))
		c.JSON(http.StatusBadGateway, gin.H{"error": "payment gateway error"})
		return
	}

	var cfOrderResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cfOrderResp); err != nil {
		logger.ErrorLogger.Errorf("Failed to decode Cashfree order response: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid response from payment gateway"})
		return
	}

	cfOrderID, _ := cfOrderResp["order_id"].(string)
	cfPaymentSessionID, _ := cfOrderResp["payment_session_id"].(string)

	var dbOrderID uuid.UUID
	err = pc.DB.QueryRow(ctx,
		`INSERT INTO orders (order_id, customer_id, service_id, start_time, end_time, amount, currency, cf_order_id, payment_session_id, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
         RETURNING id`,
		cfOrderID, customerID, req.ServiceID, req.StartTime.UTC(), req.EndTime.UTC(), service.Price, req.Currency,
		cfOrderID, cfPaymentSessionID, OrderStatusPending,
	).Scan(&dbOrderID)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to insert order in DB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save order"})
		return
	}

	logger.InfoLogger.Infof("Order created: %s for customer: %s", cfOrderID, customerID)

	response := gin.H{
		"order_id": cfOrderID,
		"payment":  cfOrderResp,
	}

	if len(req.PaymentMethod) > 0 {
		paymentPayload := map[string]interface{}{
			"payment_session_id": cfPaymentSessionID,
			"payment_method":     req.PaymentMethod,
		}

		jsonPaymentPayload, err := json.Marshal(paymentPayload)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to marshal payment payload: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to prepare payment"})
			return
		}

		paymentResp, err := pc.makeRequest(ctx, "POST", "/orders/sessions", bytes.NewBuffer(jsonPaymentPayload))
		if err != nil {
			logger.ErrorLogger.Errorf("Cashfree payment initiation failed: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "payment gateway error"})
			return
		}
		defer paymentResp.Body.Close()

		if paymentResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(paymentResp.Body)
			logger.ErrorLogger.Errorf("Cashfree payment error [%d]: %s", paymentResp.StatusCode, string(body))
			c.JSON(http.StatusBadGateway, gin.H{"error": "payment initiation failed", "details": string(body)})
			return
		}

		var cfPaymentResp map[string]interface{}
		if err := json.NewDecoder(paymentResp.Body).Decode(&cfPaymentResp); err != nil {
			logger.ErrorLogger.Errorf("Failed to decode Cashfree payment response: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "invalid response from payment gateway"})
			return
		}

		response["payment"] = cfPaymentResp
	}

	c.JSON(http.StatusOK, response)
}

// CreateRefund creates a refund for an order
func (pc *PaymentController) CreateRefund(c *gin.Context) {
	orderID := c.Param("order_id")
	if orderID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "order_id required"})
		return
	}

	var req CreateRefundRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Invalid refund request for order %s: %v", orderID, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	ctx := c.Request.Context()

	var orderAmount float64
	err := pc.DB.QueryRow(ctx,
		`SELECT amount FROM orders WHERE order_id = $1 AND cf_payment_id IS NOT NULL AND status = $2`,
		orderID, OrderStatusPaid).Scan(&orderAmount)

	if err != nil {
		if err == pgx.ErrNoRows {
			logger.ErrorLogger.Errorf("No paid order found for order_id=%s", orderID)
			c.JSON(http.StatusNotFound, gin.H{"error": "paid order not found"})
		} else {
			logger.ErrorLogger.Errorf("DB query error checking order %s: %v", orderID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		}
		return
	}

	if req.Amount > orderAmount {
		c.JSON(http.StatusBadRequest, gin.H{"error": "refund amount exceeds order amount"})
		return
	}

	refundID := "refund_" + uuid.New().String()

	payload := map[string]interface{}{
		"refund_amount": req.Amount,
		"refund_id":     refundID,
		"refund_note":   req.Note,
	}
	jsonPayload, _ := json.Marshal(payload)

	resp, err := pc.makeRequest(ctx, "POST", "/orders/"+orderID+"/refunds", bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.ErrorLogger.Errorf("Refund gateway error for order %s: %v", orderID, err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "refund gateway error"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.ErrorLogger.Errorf("Refund creation failed for order %s: status=%d body=%s", orderID, resp.StatusCode, string(body))
		c.JSON(http.StatusBadGateway, gin.H{"error": "refund creation failed"})
		return
	}

	var cfResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		logger.ErrorLogger.Errorf("Failed to decode refund response for order %s: %v", orderID, err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid refund response"})
		return
	}

	_, err = pc.DB.Exec(ctx,
		`INSERT INTO refunds (order_id, refund_id, amount, status, note, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
		orderID, refundID, req.Amount, StatusRefundPending, req.Note)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to save refund for order %s: %v", orderID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save refund"})
		return
	}

	logger.InfoLogger.Infof("Refund created: %s for order: %s amount=%.2f", refundID, orderID, req.Amount)

	c.JSON(http.StatusOK, gin.H{
		"refund_id": refundID,
		"refund":    cfResp,
	})
}

// GetOrder retrieves an order by ID for the authenticated user
func (pc *PaymentController) GetOrder(c *gin.Context) {
	orderID := c.Param("order_id")
	if orderID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "order_id required"})
		return
	}

	customerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		if err.Error() == "unauthorized" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	ctx := c.Request.Context()
	var order struct {
		ID               uuid.UUID `db:"id"`
		OrderID          string    `db:"order_id"`
		ServiceID        uuid.UUID `db:"service_id"`
		StartTime        time.Time `db:"start_time"`
		EndTime          time.Time `db:"end_time"`
		Amount           float64   `db:"amount"`
		PaymentSessionID string    `db:"payment_session_id"`
		Currency         string    `db:"currency"`
		CreatedAt        time.Time `db:"created_at"`
	}

	err = pc.DB.QueryRow(ctx,
		`SELECT id, order_id, service_id, start_time, end_time, amount, payment_session_id, currency, created_at
         FROM orders 
         WHERE customer_id = $1 AND order_id = $2`,
		customerID, orderID).Scan(
		&order.ID, &order.OrderID, &order.ServiceID, &order.StartTime, &order.EndTime, &order.Amount, &order.PaymentSessionID,
		&order.Currency, &order.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "order not found"})
		} else {
			logger.ErrorLogger.Errorf("Failed to get order %s for customer %s: %v", orderID, customerID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"order_id":           order.OrderID,
		"service_id":         order.ServiceID,
		"start_time":         order.StartTime,
		"end_time":           order.EndTime,
		"amount":             order.Amount,
		"currency":           order.Currency,
		"created_at":         order.CreatedAt,
		"payment_session_id": order.PaymentSessionID,
		"payment": gin.H{
			"order_amount":   order.Amount,
			"order_currency": order.Currency,
		},
	})
}

// GetOrderHistory gets order history for a customer
func (pc *PaymentController) GetOrderHistory(c *gin.Context) {
	customerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		if err.Error() == "unauthorized" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	limit := 20
	offset := 0
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	ctx := c.Request.Context()
	rows, err := pc.DB.Query(ctx,
		`SELECT id, order_id, service_id, start_time, end_time, amount, currency, created_at
         FROM orders 
         WHERE customer_id = $1 
         ORDER BY created_at DESC 
         LIMIT $2 OFFSET $3`,
		customerID, limit, offset)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to query order history for customer %s: %v", customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}
	defer rows.Close()

	var orders []map[string]interface{}
	for rows.Next() {
		var id uuid.UUID
		var orderID string
		var serviceID uuid.UUID
		var startTime time.Time
		var endTime time.Time
		var amount float64
		var currency string
		var createdAt time.Time

		if err := rows.Scan(&id, &orderID, &serviceID, &startTime, &endTime, &amount, &currency, &createdAt); err != nil {
			logger.ErrorLogger.Errorf("Failed to scan order row: %v", err)
			continue
		}

		orders = append(orders, map[string]interface{}{
			"id":         id,
			"order_id":   orderID,
			"service_id": serviceID,
			"start_time": startTime,
			"end_time":   endTime,
			"amount":     amount,
			"currency":   currency,
			"created_at": createdAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"orders": orders,
		"limit":  limit,
		"offset": offset,
	})
}

// WebhookHealthCheck provides webhook system health status
func (pc *PaymentController) WebhookHealthCheck(c *gin.Context) {
	ctx := c.Request.Context()

	var lastEvent struct {
		EventType string    `json:"event_type"`
		CreatedAt time.Time `json:"created_at"`
		Processed bool      `json:"processed"`
	}

	err := pc.DB.QueryRow(ctx,
		`SELECT event_type, created_at, processed 
         FROM webhook_events 
         ORDER BY created_at DESC 
         LIMIT 1`).Scan(&lastEvent.EventType, &lastEvent.CreatedAt, &lastEvent.Processed)

	if err != nil && err != pgx.ErrNoRows {
		logger.ErrorLogger.Errorf("Failed to get last webhook event: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "health check failed"})
		return
	}

	var count int
	err = pc.DB.QueryRow(ctx,
		`SELECT COUNT(*) FROM webhook_events WHERE created_at > NOW() - INTERVAL '24 hours'`).Scan(&count)
	if err != nil && err != pgx.ErrNoRows {
		logger.ErrorLogger.Errorf("Failed to count recent webhook events: %v", err)
	}

	var unprocessed int
	err = pc.DB.QueryRow(ctx,
		`SELECT COUNT(*) FROM webhook_events WHERE NOT processed`).Scan(&unprocessed)
	if err != nil && err != pgx.ErrNoRows {
		logger.ErrorLogger.Errorf("Failed to count unprocessed events: %v", err)
	}

	response := gin.H{
		"status":             "healthy",
		"webhook_configured": pc.WebhookSecret != "",
		"events_24h":         count,
		"unprocessed_events": unprocessed,
	}

	if err != pgx.ErrNoRows {
		response["last_event"] = lastEvent
	}

	c.JSON(http.StatusOK, response)
}

// GetUnavailableTimes retrieves all confirmed (booked) time slots for a service on a specific date
func (pc *PaymentController) GetUnavailableTimes(c *gin.Context) {
	serviceIDStr := c.Param("service_id")
	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID format"})
		return
	}

	dateStr := c.Query("date")
	if dateStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Query parameter 'date' is required in YYYY-MM-DD format"})
		return
	}

	bookingDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format, use YYYY-MM-DD"})
		return
	}

	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	if bookingDate.Before(today) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Booking date cannot be in the past"})
		return
	}

	startOfDay := time.Date(bookingDate.Year(), bookingDate.Month(), bookingDate.Day(), 0, 0, 0, 0, time.UTC)
	endOfDay := startOfDay.Add(24 * time.Hour)

	logger.InfoLogger.Infof("Fetching unavailable times for service=%s, date=%s, UTC range=%s - %s",
		serviceID, dateStr, startOfDay.Format(time.RFC3339), endOfDay.Format(time.RFC3339))

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	times, err := payment_models.GetBookedTimesForServiceDate(ctx, pc.DB, serviceID, startOfDay, endOfDay)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch unavailable times for service %s on %s: %v", serviceID, dateStr, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch unavailable times"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"times": times})
}

// WebhookEvent structure
type WebhookEvent struct {
	Type      string          `json:"type"`
	EventTime string          `json:"event_time"`
	Data      json.RawMessage `json:"data"`
}

// PaymentWebhookData structure
type PaymentWebhookData struct {
	Order   OrderData   `json:"order"`
	Payment PaymentData `json:"payment"`
}

// OrderData structure
type OrderData struct {
	OrderID       string  `json:"order_id"`
	OrderAmount   float64 `json:"order_amount"`
	OrderCurrency string  `json:"order_currency"`
	OrderStatus   string  `json:"order_status"`
}

// PaymentData structure
type PaymentData struct {
	CfPaymentID     int64                  `json:"cf_payment_id"`
	PaymentStatus   string                 `json:"payment_status"`
	PaymentAmount   float64                `json:"payment_amount"`
	PaymentCurrency string                 `json:"payment_currency"`
	BankReference   string                 `json:"bank_reference"`
	PaymentMethod   map[string]interface{} `json:"payment_method"`
}

// RefundWebhookData structure
type RefundWebhookData struct {
	Order  OrderData  `json:"order"`
	Refund RefundData `json:"refund"`
}

// RefundData structure
type RefundData struct {
	CfRefundID      string                   `json:"cf_refund_id"`
	RefundID        string                   `json:"refund_id"`
	RefundStatus    string                   `json:"refund_status"`
	RefundAmount    float64                  `json:"refund_amount"`
	RefundNote      string                   `json:"refund_note"`
	ProcessedAt     string                   `json:"processed_at"`
	RefundReversals []map[string]interface{} `json:"refund_reversals"`
}

// CreateOrderRequest structure
type CreateOrderRequest struct {
	Currency      string                 `json:"currency" binding:"required,len=3"`
	ServiceID     uuid.UUID              `json:"service_id" binding:"required"`
	StartTime     time.Time              `json:"start_time" binding:"required"`
	EndTime       time.Time              `json:"end_time" binding:"required"`
	UpiID         string                 `json:"upi_id"`
	PaymentMethod map[string]interface{} `json:"payment_method"`
}

// CreateRefundRequest structure
type CreateRefundRequest struct {
	Amount float64 `json:"amount" binding:"required,gt=0"`
	Note   string  `json:"note"`
}
