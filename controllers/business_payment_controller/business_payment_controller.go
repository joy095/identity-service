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
	"github.com/joy095/identity/models/user_models"
)

// Order status constants
const (
	StatusPending = "pending"
	StatusPaid    = "paid"
	StatusFailed  = "failed"
	StatusExpired = "expired"
)

// Refund status constants
const (
	StatusRefundPending  = "pending"
	StatusRefundSuccess  = "success"
	StatusRefundFailed   = "failed"
	StatusRefundReversed = "reversed"
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
func NewPaymentController(db *pgxpool.Pool) *PaymentController {
	clientID := os.Getenv("CASHFREE_CLIENT_ID")
	clientSecret := os.Getenv("CASHFREE_CLIENT_SECRET")
	apiVersion := os.Getenv("CASHFREE_API_VERSION")
	webhookSecret := os.Getenv("CASHFREE_WEBHOOK_SECRET")

	if clientID == "" || clientSecret == "" || apiVersion == "" || webhookSecret == "" {
		panic("Required Cashfree environment variables not set")
	}

	baseURL := os.Getenv("CASHFREE_BASE_URL")
	if baseURL == "" {
		baseURL = "https://sandbox.cashfree.com/pg" // Default to sandbox
	}

	return &PaymentController{
		DB:            db,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		APIVersion:    apiVersion,
		BaseURL:       baseURL,
		WebhookSecret: webhookSecret,
		// Initialize a single, reusable HTTP client
		HttpClient: &http.Client{Timeout: 15 * time.Second},
	}
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

	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

// PaymentWebhook is the single entry point for all Cashfree webhooks.
func (pc *PaymentController) PaymentWebhook(c *gin.Context) {
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to read webhook body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	// 1. Verify webhook signature (CRITICAL SECURITY STEP)
	if !pc.verifyWebhookSignature(c, bodyBytes) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid signature"})
		return
	}

	// 2. Parse the generic event structure to determine the type
	var event WebhookEvent
	if err := json.Unmarshal(bodyBytes, &event); err != nil {
		logger.ErrorLogger.Errorf("Invalid webhook payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	ctx := c.Request.Context()

	// 3. Log the raw event for audit and debugging purposes
	// This is a best practice, allowing you to replay events if processing fails.
	_, err = pc.DB.Exec(ctx,
		`INSERT INTO webhook_events (event_type, raw_payload) VALUES ($1, $2)`,
		event.Type, string(bodyBytes))
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to log webhook event: %v", err)
		// Do not stop processing, just log the failure
	}

	// 4. Route the event to the appropriate handler
	switch event.Type {
	case "PAYMENT_SUCCESS_WEBHOOK", "ORDER_PAID":
		pc.handlePaymentSuccess(ctx, event.Data)

	case "PAYMENT_FAILED_WEBHOOK", "PAYMENT_USER_DROPPED_WEBHOOK":
		pc.handlePaymentFailure(ctx, event.Data)

	case "ORDER_EXPIRED", "LINK_EXPIRED":
		pc.handleOrderExpired(ctx, event.Data)

	case "LINK_CANCELLED":
		pc.handleOrderCancelled(ctx, event.Data)

	case "REFUND_SUCCESS_WEBHOOK":
		pc.handleRefundSuccess(ctx, event.Data)

	case "REFUND_FAILURE_WEBHOOK", "REFUND_REVERSED_WEBHOOK":
		pc.handleRefundFailure(ctx, event.Data, event.Type)

	default:
		logger.InfoLogger.Infof("Unhandled webhook event type received: %s", event.Type)
	}

	c.JSON(http.StatusOK, gin.H{"status": "processed"})
}

// verifyWebhookSignature verifies the HMAC-SHA256 signature from Cashfree.
func (pc *PaymentController) verifyWebhookSignature(c *gin.Context, body []byte) bool {
	signature := c.GetHeader("x-webhook-signature")
	if signature == "" {
		logger.ErrorLogger.Error("Missing webhook signature header")
		return false
	}

	mac := hmac.New(sha256.New, []byte(pc.WebhookSecret))
	mac.Write(body)
	expectedSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	fmt.Printf("Cashfree Debug | ReceivedSig=%s | ExpectedSig=%s | Body=%s", signature, expectedSignature, string(body))

	if !hmac.Equal([]byte(expectedSignature), []byte(signature)) {
		fmt.Errorf(
			"Signature mismatch | Expected=%s | Received=%s | Body=%s",
			expectedSignature, signature, string(body),
		)
		return false
	}

	return true
}

// --- Webhook Handler Implementations ---

func (pc *PaymentController) handlePaymentSuccess(ctx context.Context, data json.RawMessage) {
	var webhookData PaymentWebhookData
	if err := json.Unmarshal(data, &webhookData); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse payment success data: %v", err)
		return
	}

	orderID := webhookData.Order.OrderID
	payment := webhookData.Payment

	tx, err := pc.DB.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_BEGIN_FAIL] PaymentSuccess for %s: %v", orderID, err)
		return
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`UPDATE orders 
		 SET status = $1, cf_payment_id = $2, payment_method = $3, payment_time = $4, bank_reference = $5, updated_at = NOW()
		 WHERE order_id = $6`,
		StatusPaid, payment.CfPaymentID, payment.PaymentMethod, payment.PaymentTime, payment.BankReference, orderID)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update order for success failed for %s: %v", orderID, err)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("[TX_COMMIT_FAIL] PaymentSuccess for %s: %v", orderID, err)
		return
	}

	logger.InfoLogger.Infof("✅ Payment success processed for order: %s", orderID)
}

func (pc *PaymentController) handlePaymentFailure(ctx context.Context, data json.RawMessage) {
	var webhookData PaymentWebhookData
	if err := json.Unmarshal(data, &webhookData); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse payment failure data: %v", err)
		return
	}

	orderID := webhookData.Order.OrderID
	updateOrderStatus(ctx, pc.DB, orderID, StatusFailed, "❌ Payment failure/dropped processed for order: %s")
}

type OrderOnlyWebhookData struct {
	Order OrderData `json:"order"`
}

func (pc *PaymentController) handleOrderExpired(ctx context.Context, data json.RawMessage) {
	var webhookData OrderOnlyWebhookData
	if err := json.Unmarshal(data, &webhookData); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse order expired data: %v", err)
		return
	}

	orderID := webhookData.Order.OrderID
	updateOrderStatus(ctx, pc.DB, orderID, StatusExpired, "⌛ Order expired for: %s")
}

func (pc *PaymentController) handleOrderCancelled(ctx context.Context, data json.RawMessage) {
	var webhookData OrderOnlyWebhookData
	if err := json.Unmarshal(data, &webhookData); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse order cancelled data: %v", err)
		return
	}

	orderID := webhookData.Order.OrderID
	updateOrderStatus(ctx, pc.DB, orderID, StatusFailed, "🚫 Order cancelled for: %s")
}

type RefundWebhookData struct {
	Order  OrderData  `json:"order"`
	Refund RefundData `json:"refund"`
}

type RefundData struct {
	CfRefundID      string                   `json:"cf_refund_id"`
	RefundID        string                   `json:"refund_id"`
	RefundStatus    string                   `json:"refund_status"`
	RefundAmount    float64                  `json:"refund_amount"`
	RefundNote      string                   `json:"refund_note"`
	ProcessedAt     string                   `json:"processed_at"`
	RefundReversals []map[string]interface{} `json:"refund_reversals"`
}

func (pc *PaymentController) handleRefundSuccess(ctx context.Context, data json.RawMessage) {
	var webhookData RefundWebhookData
	if err := json.Unmarshal(data, &webhookData); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse refund success data: %v", err)
		return
	}

	refund := webhookData.Refund
	tx, err := pc.DB.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_BEGIN_FAIL] RefundSuccess for %s: %v", refund.RefundID, err)
		return
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`UPDATE refunds 
		 SET status = $1, cf_refund_id = $2, processed_at = $3, updated_at = NOW()
		 WHERE refund_id = $4`,
		StatusRefundSuccess, refund.CfRefundID, refund.ProcessedAt, refund.RefundID)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update refund for success failed for %s: %v", refund.RefundID, err)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("[TX_COMMIT_FAIL] RefundSuccess for %s: %v", refund.RefundID, err)
		return
	}
	logger.InfoLogger.Infof("✅ Refund success processed for refund_id: %s", refund.RefundID)
}

func (pc *PaymentController) handleRefundFailure(ctx context.Context, data json.RawMessage, eventType string) {
	var webhookData RefundWebhookData
	if err := json.Unmarshal(data, &webhookData); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse refund failure/reversal data: %v", err)
		return
	}

	refundID := webhookData.Refund.RefundID
	newStatus := StatusRefundFailed
	if eventType == "REFUND_REVERSED_WEBHOOK" {
		newStatus = StatusRefundReversed
	}

	tx, err := pc.DB.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_BEGIN_FAIL] RefundFailure for %s: %v", refundID, err)
		return
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`UPDATE refunds SET status = $1, updated_at = NOW() WHERE refund_id = $2`,
		newStatus, refundID)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update refund for failure failed for %s: %v", refundID, err)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("[TX_COMMIT_FAIL] RefundFailure for %s: %v", refundID, err)
		return
	}
	logger.InfoLogger.Infof("❌ Refund %s processed for refund_id: %s", newStatus, refundID)
}

// Helper function to update only the status of an order within a transaction.
func updateOrderStatus(ctx context.Context, db *pgxpool.Pool, orderID, status, logMessage string) {
	tx, err := db.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_BEGIN_FAIL] UpdateOrderStatus for %s: %v", orderID, err)
		return
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`UPDATE orders SET status = $1, updated_at = NOW() WHERE order_id = $2 AND status = 'pending'`,
		status, orderID)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update order status failed for %s: %v", orderID, err)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("[TX_COMMIT_FAIL] UpdateOrderStatus for %s: %v", orderID, err)
		return
	}

	logger.InfoLogger.Infof(logMessage, orderID)
}

// CreateOrderRequest represents the order creation request
type CreateOrderRequest struct {
	Amount   float64 `json:"amount" binding:"required,gt=0"`
	Currency string  `json:"currency" binding:"required,len=3"`
}

// CreateOrder creates a new payment order
func (pc *PaymentController) CreateOrder(c *gin.Context) {
	// Get customer ID from JWT token
	customerIDStr, exists := c.Get("sub")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	customerID, err := uuid.Parse(customerIDStr.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid customer ID"})
		return
	}

	// Get user details
	user, err := user_models.GetUserByID(c.Request.Context(), pc.DB, customerID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user"})
		return
	}

	if user.Phone == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user phone required"})
		return
	}

	// Parse request
	var req CreateOrderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Generate unique order ID
	orderID := "order_" + uuid.New().String()

	// Create Cashfree order
	payload := map[string]interface{}{
		"order_id":       orderID,
		"order_amount":   req.Amount,
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

	resp, err := pc.makeRequest(c.Request.Context(), "POST", "/orders", bytes.NewBuffer(jsonPayload))
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

	var cfResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid response from payment gateway"})
		return
	}

	// Save order to database
	ctx := c.Request.Context()
	cfOrderID, _ := cfResp["cf_order_id"].(string)
	paymentSessionID, _ := cfResp["payment_session_id"].(string)

	var dbOrderID uuid.UUID
	err = pc.DB.QueryRow(ctx,
		`INSERT INTO orders (customer_id, order_id, cf_order_id, amount, currency, status, payment_session_id)
		  VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		customerID, orderID, cfOrderID, req.Amount, req.Currency, StatusPending, paymentSessionID,
	).Scan(&dbOrderID)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to save order: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create order"})
		return
	}

	logger.InfoLogger.Infof("Order created: %s for customer: %s", orderID, customerID)

	c.JSON(http.StatusOK, gin.H{
		"order_id": orderID,
		"payment":  cfResp,
	})
}

// PaymentRequest for processing payments
type PaymentRequest struct {
	PaymentSessionID string                 `json:"payment_session_id" binding:"required"`
	PaymentMethod    map[string]interface{} `json:"payment_method" binding:"required"`
}

// ProcessPayment handles payment processing
func (pc *PaymentController) ProcessPayment(c *gin.Context) {
	var req PaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	payload := map[string]interface{}{
		"payment_session_id": req.PaymentSessionID,
		"payment_method":     req.PaymentMethod,
	}

	jsonPayload, _ := json.Marshal(payload)
	resp, err := pc.makeRequest(c.Request.Context(), "POST", "/orders/sessions", bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "payment gateway error"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.JSON(http.StatusBadGateway, gin.H{"error": "payment failed", "details": string(body)})
		return
	}

	var cfResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid response"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"payment": cfResp})
}

// UPI payment structures
type UPIRequest struct {
	PaymentSessionID string `json:"payment_session_id" binding:"required"`
	UPIID            string `json:"upi_id"`
}

// ProcessUPIPayment handles UPI payments with different channels
func (pc *PaymentController) ProcessUPIPayment(c *gin.Context, channel string, requireUPIID bool) {
	var req UPIRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Validate UPI ID if required
	if requireUPIID {
		upiRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.\-_]*[a-zA-Z0-9])?@[a-zA-Z][a-zA-Z0-9]*$`)
		if !upiRegex.MatchString(req.UPIID) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid UPI ID"})
			return
		}
	}

	upiData := map[string]string{"channel": channel}
	if req.UPIID != "" {
		upiData["upi_id"] = req.UPIID
	}

	payload := map[string]interface{}{
		"payment_session_id": req.PaymentSessionID,
		"payment_method": map[string]interface{}{
			"upi": upiData,
		},
	}

	jsonPayload, _ := json.Marshal(payload)
	resp, err := pc.makeRequest(c.Request.Context(), "POST", "/orders/sessions", bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "payment gateway error"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.JSON(http.StatusBadGateway, gin.H{"error": "UPI payment failed", "details": string(body)})
		return
	}

	var cfResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid response"})
		return
	}

	c.JSON(http.StatusOK, cfResp)
}

// UPI payment endpoints
func (pc *PaymentController) PayUPIQR(c *gin.Context)      { pc.ProcessUPIPayment(c, "qrcode", false) }
func (pc *PaymentController) PayUPIIntent(c *gin.Context)  { pc.ProcessUPIPayment(c, "link", false) }
func (pc *PaymentController) PayUPICollect(c *gin.Context) { pc.ProcessUPIPayment(c, "collect", true) }

// Webhook structures based on Cashfree documentation
type WebhookEvent struct {
	Type      string          `json:"type"`
	EventTime string          `json:"event_time"`
	Data      json.RawMessage `json:"data"`
}

type PaymentWebhookData struct {
	Order   OrderData   `json:"order"`
	Payment PaymentData `json:"payment"`
}

type OrderData struct {
	OrderID       string  `json:"order_id"`
	OrderAmount   float64 `json:"order_amount"`
	OrderCurrency string  `json:"order_currency"`
	OrderStatus   string  `json:"order_status"`
}

type PaymentData struct {
	CfPaymentID     int64                  `json:"cf_payment_id"`
	PaymentStatus   string                 `json:"payment_status"`
	PaymentAmount   float64                `json:"payment_amount"`
	PaymentCurrency string                 `json:"payment_currency"`
	PaymentTime     string                 `json:"payment_time"`
	BankReference   string                 `json:"bank_reference"`
	PaymentMethod   map[string]interface{} `json:"payment_method"`
}

// GetOrderStatus retrieves order status with real-time sync
func (pc *PaymentController) GetOrderStatus(c *gin.Context) {
	orderID := c.Param("order_id")
	if orderID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "order_id required"})
		return
	}

	ctx := c.Request.Context()
	var order struct {
		ID            uuid.UUID              `json:"id"`
		OrderID       string                 `json:"order_id"`
		Status        string                 `json:"status"`
		Amount        float64                `json:"amount"`
		Currency      string                 `json:"currency"`
		PaymentMethod map[string]interface{} `json:"payment_method,omitempty"`
		PaymentTime   *string                `json:"payment_time,omitempty"`
		BankReference *string                `json:"bank_reference,omitempty"`
		CreatedAt     time.Time              `json:"created_at"`
	}

	err := pc.DB.QueryRow(ctx,
		`SELECT id, order_id, status, amount, currency, 
			    COALESCE(payment_method, '{}'::jsonb), payment_time, bank_reference, created_at
		 FROM orders WHERE order_id = $1`,
		orderID).Scan(
		&order.ID, &order.OrderID, &order.Status, &order.Amount, &order.Currency,
		&order.PaymentMethod, &order.PaymentTime, &order.BankReference, &order.CreatedAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "order not found"})
		} else {
			logger.ErrorLogger.Errorf("Failed to get order: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		}
		return
	}

	// If order is still pending and older than 5 minutes, sync with Cashfree as a fallback.
	// Webhooks should handle most cases, but this adds resilience.
	if order.Status == StatusPending && time.Since(order.CreatedAt) > 5*time.Minute {
		pc.syncOrderStatus(ctx, orderID)
		// Re-fetch updated status
		pc.DB.QueryRow(ctx, `SELECT status FROM orders WHERE order_id = $1`, orderID).Scan(&order.Status)
	}

	c.JSON(http.StatusOK, gin.H{"order": order})
}

// syncOrderStatus syncs order status with Cashfree
func (pc *PaymentController) syncOrderStatus(ctx context.Context, orderID string) {
	resp, err := pc.makeRequest(ctx, "GET", "/orders/"+orderID, nil)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to sync order status: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var cfResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		return
	}

	orderStatus, ok := cfResp["order_status"].(string)
	if !ok {
		return
	}

	// Map Cashfree status to internal status
	var dbStatus string
	switch orderStatus {
	case "PAID":
		dbStatus = StatusPaid
	case "EXPIRED", "TERMINATED":
		dbStatus = StatusExpired
	default:
		return // No update needed
	}

	// Update database
	_, err = pc.DB.Exec(ctx,
		`UPDATE orders SET status = $1, updated_at = NOW() WHERE order_id = $2`,
		dbStatus, orderID)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update order status for %s: %v", orderID, err)
		return
	}

	logger.InfoLogger.Infof("Order status synced: %s -> %s", orderID, dbStatus)
}

// CreateRefundRequest represents refund creation request
type CreateRefundRequest struct {
	Amount float64 `json:"amount" binding:"required,gt=0"`
	Note   string  `json:"note"`
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Check if order exists and is paid
	ctx := c.Request.Context()
	var orderAmount float64
	err := pc.DB.QueryRow(ctx,
		`SELECT amount FROM orders WHERE order_id = $1 AND status = $2`,
		orderID, StatusPaid).Scan(&orderAmount)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "paid order not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		}
		return
	}

	if req.Amount > orderAmount {
		c.JSON(http.StatusBadRequest, gin.H{"error": "refund amount exceeds order amount"})
		return
	}

	// Generate refund ID
	refundID := "refund_" + uuid.New().String()

	// Create refund with Cashfree
	payload := map[string]interface{}{
		"refund_amount": req.Amount,
		"refund_id":     refundID,
		"refund_note":   req.Note,
	}

	jsonPayload, _ := json.Marshal(payload)
	resp, err := pc.makeRequest(ctx, "POST", "/orders/"+orderID+"/refunds", bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "refund gateway error"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.ErrorLogger.Errorf("Refund creation failed: %s", string(body))
		c.JSON(http.StatusBadGateway, gin.H{"error": "refund creation failed"})
		return
	}

	var cfResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid refund response"})
		return
	}

	// Save refund to database
	_, err = pc.DB.Exec(ctx,
		`INSERT INTO refunds (order_id, refund_id, amount, status, note)
		 VALUES ($1, $2, $3, $4, $5)`,
		orderID, refundID, req.Amount, StatusPending, req.Note)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to save refund: %v", err)
	}

	logger.InfoLogger.Infof("Refund created: %s for order: %s", refundID, orderID)

	c.JSON(http.StatusOK, gin.H{
		"refund_id": refundID,
		"refund":    cfResp,
	})
}

// GetOrderHistory gets order history for a customer
func (pc *PaymentController) GetOrderHistory(c *gin.Context) {
	customerIDStr, exists := c.Get("sub")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	customerID, _ := uuid.Parse(customerIDStr.(string))

	// Pagination
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
		`SELECT id, order_id, amount, currency, status, created_at
		 FROM orders 
		 WHERE customer_id = $1 
		 ORDER BY created_at DESC 
		 LIMIT $2 OFFSET $3`,
		customerID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}
	defer rows.Close()

	var orders []map[string]interface{}
	for rows.Next() {
		var id uuid.UUID
		var orderID string
		var amount float64
		var currency string
		var status string
		var createdAt time.Time

		if err := rows.Scan(&id, &orderID, &amount, &currency, &status, &createdAt); err != nil {
			continue
		}

		orders = append(orders, map[string]interface{}{
			"id":         id,
			"order_id":   orderID,
			"amount":     amount,
			"currency":   currency,
			"status":     status,
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

	// Check last webhook received
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "health check failed"})
		return
	}

	// Count events in last 24 hours
	var count int
	err = pc.DB.QueryRow(ctx,
		`SELECT COUNT(*) FROM webhook_events WHERE created_at > NOW() - INTERVAL '24 hours'`).Scan(&count)
	if err != nil && err != pgx.ErrNoRows {
		logger.ErrorLogger.Errorf("Failed to count recent webhook events: %v", err)
	}

	// Count unprocessed events
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
