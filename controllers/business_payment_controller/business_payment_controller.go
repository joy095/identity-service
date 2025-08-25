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

// Constants for reused variables
const (
	OrderIDPrefix        = "order_"
	BookingStatusPending = "pending"
	BookingStatusPaid    = "paid"
	BookingStatusFailed  = "failed"
	PaymentStatusPending = "pending"
	PaymentStatusPaid    = "paid"
	PaymentStatusFailed  = "failed"
	RefundStatusPending  = "pending"
	RefundStatusSuccess  = "success"
	RefundStatusFailed   = "failed"
)

// BusinessPaymentController holds dependencies for business-related operations.
type BusinessPaymentController struct {
	DB                 *pgxpool.Pool
	ClientID           string
	ClientSecret       string
	APIVersion         string
	BaseURL            string
	PayoutClientID     string
	PayoutClientSecret string
	PayoutBaseURL      string
	WebhookSecret      string
}

// NewBusinessPaymentController creates a new instance of BusinessPaymentController.
func NewBusinessPaymentController(db *pgxpool.Pool) *BusinessPaymentController {
	clientID := os.Getenv("CASHFREE_CLIENT_ID")
	clientSecret := os.Getenv("CASHFREE_CLIENT_SECRET")
	apiVersion := os.Getenv("X_API_VERSION")

	if clientID == "" || clientSecret == "" || apiVersion == "" {
		panic("Required Cashfree environment variables not set: CASHFREE_CLIENT_ID, CASHFREE_CLIENT_SECRET, X_API_VERSION")
	}

	baseURL := os.Getenv("CASHFREE_BASE_URL")
	if baseURL == "" {
		baseURL = "https://sandbox.cashfree.com/pg"
	}

	payoutClientID := os.Getenv("CASHFREE_PAYOUT_CLIENT_ID")
	payoutClientSecret := os.Getenv("CASHFREE_PAYOUT_CLIENT_SECRET")
	payoutBaseURL := os.Getenv("CASHFREE_PAYOUT_BASE_URL")
	if payoutBaseURL == "" {
		payoutBaseURL = "https://payout-sandbox.cashfree.com"
	}

	webhookSecret := os.Getenv("CASHFREE_WEBHOOK_SECRET")
	if webhookSecret == "" {
		panic("Required Cashfree webhook secret not set: CASHFREE_WEBHOOK_SECRET")
	}

	return &BusinessPaymentController{
		DB:                 db,
		ClientID:           clientID,
		ClientSecret:       clientSecret,
		APIVersion:         apiVersion,
		BaseURL:            baseURL,
		PayoutClientID:     payoutClientID,
		PayoutClientSecret: payoutClientSecret,
		PayoutBaseURL:      payoutBaseURL,
		WebhookSecret:      webhookSecret,
	}
}

func (bc *BusinessPaymentController) callCashfree(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, bc.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("x-client-id", bc.ClientID)
	req.Header.Set("x-client-secret", bc.ClientSecret)
	req.Header.Set("x-api-version", bc.APIVersion)

	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

func (bc *BusinessPaymentController) callPayout(ctx context.Context, method, path string, body io.Reader, useBearer bool, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, bc.PayoutBaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if useBearer {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("X-Client-Id", bc.PayoutClientID)
		req.Header.Set("X-Client-Secret", bc.PayoutClientSecret)
	}
	// Assuming same API version for payouts
	req.Header.Set("x-api-version", bc.APIVersion)

	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

func (bc *BusinessPaymentController) getPayoutToken(ctx context.Context) (string, error) {
	resp, err := bc.callPayout(ctx, "POST", "/payout/v1/authorize", nil, false, "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return "", fmt.Errorf("authorize returned non-200: %d, body: %s", resp.StatusCode, string(b))
	}

	var cfResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		return "", err
	}

	status, ok := cfResp["status"].(string)
	if !ok || status != "SUCCESS" {
		return "", fmt.Errorf("authorize failed: %v", cfResp)
	}

	data, ok := cfResp["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("missing data in response")
	}

	token, ok := data["token"].(string)
	if !ok {
		return "", fmt.Errorf("missing token in response")
	}

	return token, nil
}

type CreatePaymentRequest struct {
	OrderCurrency string  `json:"order_currency" binding:"required,len=3"`
	OrderAmount   float64 `json:"order_amount" binding:"required,gt=0"`
}

func (bc *BusinessPaymentController) CreateOrders(c *gin.Context) {
	logger.InfoLogger.Info("CreateOrders function called")

	customerIDFromToken, exists := c.Get("sub")
	if !exists {
		logger.ErrorLogger.Error("Unauthorized: User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	customerID, err := uuid.Parse(customerIDFromToken.(string))
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid user ID from token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	user, err := user_models.GetUserByID(c.Request.Context(), bc.DB, customerID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch user data for ID %s: %v", customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user data"})
		return
	}

	if user.Phone == nil {
		logger.ErrorLogger.Errorf("User phone not found for ID %s", customerID)
		c.JSON(http.StatusNotFound, gin.H{"error": "user phone not found"})
		return
	}

	var req CreatePaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Invalid request payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if bc.ClientID == "" || bc.ClientSecret == "" || bc.APIVersion == "" {
		logger.ErrorLogger.Error("Cashfree credentials not configured")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cashfree credentials not configured"})
		return
	}

	// Prepare Cashfree order payload
	orderID := OrderIDPrefix + uuid.New().String()
	payload := map[string]interface{}{
		"order_id":       orderID,
		"order_amount":   req.OrderAmount,
		"order_currency": req.OrderCurrency,
		"customer_details": map[string]string{
			"customer_id":    customerID.String(),
			"customer_phone": *user.Phone,
		},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to serialize Cashfree payload: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize cashfree payload"})
		return
	}

	// Call Cashfree API
	resp, err := bc.callCashfree(c.Request.Context(), "POST", "/orders", bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.ErrorLogger.Errorf("Cashfree request failed: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree request failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		logger.ErrorLogger.Errorf("Cashfree returned error [%d]: %s", resp.StatusCode, string(b))
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree returned non-2xx", "status": resp.StatusCode})
		return
	}

	var cfResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		logger.ErrorLogger.Errorf("Invalid Cashfree response: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid cashfree response"})
		return
	}

	// Insert into DB using transaction
	ctx := c.Request.Context()
	tx, err := bc.DB.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to start DB transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start transaction"})
		return
	}
	defer tx.Rollback(ctx)

	var bookingID uuid.UUID

	err = tx.QueryRow(ctx,
		`INSERT INTO bookings (customer_id, status) 
     VALUES ($1, $2) 
     RETURNING id`,
		customerID,
		BookingStatusPending,
	).Scan(&bookingID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create booking for customer %s: %v", customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create booking"})
		return
	}

	cfOrderID, _ := cfResp["cf_order_id"].(string) // Cashfree sends string
	paymentSessionID, _ := cfResp["payment_session_id"].(string)

	var paymentID uuid.UUID

	err = tx.QueryRow(ctx,
		`INSERT INTO payments (booking_id, order_id, amount, currency, status, cf_order_id, payment_session_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id`,
		bookingID,
		orderID,
		req.OrderAmount,
		req.OrderCurrency,
		PaymentStatusPending,
		cfOrderID,
		paymentSessionID,
	).Scan(&paymentID)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create payment for booking %s: %v", bookingID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create payment"})
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("Failed to commit transaction for booking %s: %v", bookingID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to commit transaction"})
		return
	}

	logger.InfoLogger.Infof("Order created successfully: booking_id=%s, order_id=%s", bookingID, orderID)

	// Respond
	c.JSON(http.StatusOK, gin.H{
		"booking_id": bookingID,
		"order_id":   orderID,
		"payment":    cfResp,
	})
}

type PayPaymentRequest struct {
	PaymentSessionId string                 `json:"payment_session_id" binding:"required"`
	PaymentMethod    map[string]interface{} `json:"payment_method" binding:"required"`
}

func (bc *BusinessPaymentController) PayPayment(c *gin.Context) {

	var req PayPaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Failed to bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	payload := map[string]interface{}{
		"payment_session_id": req.PaymentSessionId,
		"payment_method":     req.PaymentMethod,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize cashfree payload"})
		return
	}

	resp, err := bc.callCashfree(c.Request.Context(), "POST", "/orders/sessions", bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree request failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree returned non-2xx", "status": resp.StatusCode, "body": string(b)})
		return
	}
	var cfResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid cashfree response"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"payment": cfResp})
}

type PayUPIRequest struct {
	PaymentSessionId string `json:"payment_session_id" binding:"required"`
	UPIID            string `json:"upi_id"` // optional for collect
}

func (bc *BusinessPaymentController) processUPIPayment(c *gin.Context, channel string, responseKey string, requireUPIID bool) {
	var req PayUPIRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	reUPI := regexp.MustCompile(`^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}$`)
	if requireUPIID && !reUPI.MatchString(req.UPIID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid upi_id"})
		return
	}

	upiData := map[string]string{"channel": channel}
	if req.UPIID != "" {
		upiData["upi_id"] = req.UPIID
	}

	payload := map[string]interface{}{
		"payment_session_id": req.PaymentSessionId,
		"payment_method": map[string]interface{}{
			"upi": upiData,
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize cashfree payload"})
		return
	}

	resp, err := bc.callCashfree(c.Request.Context(), "POST", "/orders/sessions", bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree request failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree returned non-2xx", "status": resp.StatusCode, "body": string(b)})
		return
	}
	var cfResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid cashfree response"})
		return
	}

	c.JSON(http.StatusOK, gin.H{responseKey: cfResp})
}

func (bc *BusinessPaymentController) PayUPIQR(c *gin.Context) {
	bc.processUPIPayment(c, "qrcode", "qr_payment", false)
}

func (bc *BusinessPaymentController) PayUPIIntent(c *gin.Context) {
	bc.processUPIPayment(c, "link", "intent_payment", false)
}

func (bc *BusinessPaymentController) PayUPICollect(c *gin.Context) {
	bc.processUPIPayment(c, "collect", "collect_payment", true)
}

type WebhookPayload struct {
	Data struct {
		Order struct {
			OrderID string `json:"order_id"`
		} `json:"order"`
		Payment struct {
			PaymentStatus string `json:"payment_status"`
		} `json:"payment"`
	} `json:"data"`
	Type string `json:"type"`
}

func (bc *BusinessPaymentController) PaymentWebhook(c *gin.Context) {
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to read webhook body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	timestamp := c.GetHeader("x-webhook-timestamp")
	signature := c.GetHeader("x-webhook-signature")

	if timestamp == "" || signature == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing webhook headers"})
		return
	}

	msg := timestamp + "." + string(bodyBytes)
	key := []byte(bc.WebhookSecret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	expectedSig := base64.StdEncoding.EncodeToString(h.Sum(nil))

	if expectedSig != signature {
		logger.ErrorLogger.Error("Invalid webhook signature")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid signature"})
		return
	}

	var payload WebhookPayload
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		logger.ErrorLogger.Errorf("Invalid webhook payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	orderID := payload.Data.Order.OrderID
	if orderID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing order_id"})
		return
	}

	orderStatus := payload.Data.Payment.PaymentStatus

	statusMap := map[string]string{
		"SUCCESS":      PaymentStatusPaid,
		"FAILED":       PaymentStatusFailed,
		"USER_DROPPED": PaymentStatusFailed,
	}
	dbStatus, exists := statusMap[orderStatus]
	if !exists {
		logger.InfoLogger.Printf("Unknown Cashfree payment status received: %s for order_id: %s", orderStatus, orderID)
		c.JSON(http.StatusOK, gin.H{"message": "no update needed", "payment_status": orderStatus})
		return
	}

	ctx := c.Request.Context()
	tx, err := bc.DB.Begin(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start transaction"})
		return
	}
	defer tx.Rollback(ctx)

	var paymentID uuid.UUID
	var bookingID uuid.UUID
	var currentStatus string
	err = tx.QueryRow(ctx, `SELECT id, booking_id, status FROM payments WHERE order_id = $1 FOR UPDATE`, orderID).Scan(&paymentID, &bookingID, &currentStatus)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "payment not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query payment"})
		}
		return
	}

	if currentStatus == dbStatus {
		if err := tx.Commit(ctx); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "commit failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "status already updated", "payment_status": orderStatus})
		return
	}

	_, err = tx.Exec(ctx, `UPDATE payments SET status = $1 WHERE id = $2`, dbStatus, paymentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update payment"})
		return
	}

	_, err = tx.Exec(ctx, `UPDATE bookings SET status = $1 WHERE id = $2`, dbStatus, bookingID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update booking"})
		return
	}

	if err := tx.Commit(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "commit failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "status updated", "payment_status": orderStatus, "db_status": dbStatus})
}

type CreateRefundRequest struct {
	RefundAmount float64 `json:"refund_amount" binding:"required,gt=0"`
	RefundID     string  `json:"refund_id" binding:"required"`
	RefundNote   string  `json:"refund_note"`
	RefundSpeed  string  `json:"refund_speed"` // STANDARD or INSTANT
}

func (bc *BusinessPaymentController) CreateRefund(c *gin.Context) {
	orderID := c.Param("order_id")
	if orderID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing order_id"})
		return
	}

	var req CreateRefundRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	payload := map[string]interface{}{
		"refund_amount": req.RefundAmount,
		"refund_id":     req.RefundID,
		"refund_note":   req.RefundNote,
		"refund_speed":  req.RefundSpeed,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize cashfree payload"})
		return
	}

	resp, err := bc.callCashfree(c.Request.Context(), "POST", "/orders/"+orderID+"/refunds", bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree request failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree returned non-2xx", "status": resp.StatusCode, "body": string(b)})
		return
	}
	var cfResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid cashfree response"})
		return
	}

	// Save refund to DB
	ctx := c.Request.Context()
	_, err = bc.DB.Exec(ctx, `INSERT INTO refunds (order_id, refund_id, amount, status, note, created_at)
								VALUES ($1, $2, $3, $4, $5, NOW())
								ON CONFLICT (refund_id) DO NOTHING
								RETURNING id;`,
		orderID, req.RefundID, req.RefundAmount, RefundStatusPending, req.RefundNote)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save refund"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"refund": cfResp})
}

func (bc *BusinessPaymentController) GetRefund(c *gin.Context) {
	orderID := c.Param("order_id")
	refundID := c.Param("refund_id")
	if orderID == "" || refundID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing order_id or refund_id"})
		return
	}

	resp, err := bc.callCashfree(c.Request.Context(), "GET", "/orders/"+orderID+"/refunds/"+refundID, nil)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree request failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree returned error", "status": resp.StatusCode, "body": string(b)})
		return
	}

	var cfResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid cashfree response"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"refund": cfResp})
}

func (bc *BusinessPaymentController) GetOrder(c *gin.Context) {
	orderID := c.Param("order_id")
	if orderID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing order_id"})
		return
	}

	resp, err := bc.callCashfree(c.Request.Context(), "GET", "/orders/"+orderID, nil)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree request failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree returned error", "status": resp.StatusCode, "body": string(b)})
		return
	}

	var cfResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid cashfree response"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"order": cfResp})
}

type Booking struct {
	ID         uuid.UUID `json:"id"`
	CustomerID uuid.UUID `json:"customer_id"`
	Status     string    `json:"status"`
}

func (bc *BusinessPaymentController) GetBookings(c *gin.Context) {
	// Parse pagination parameters
	limit := 50 // default
	offset := 0 // default
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 1000 {
			limit = parsedLimit
		}
	}
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	ctx := c.Request.Context()
	rows, err := bc.DB.Query(ctx, `SELECT id, customer_id, status FROM bookings ORDER BY created_at LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query bookings"})
		return
	}
	defer rows.Close()

	var bookings []Booking
	for rows.Next() {
		var b Booking
		if err := rows.Scan(&b.ID, &b.CustomerID, &b.Status); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan booking"})
			return
		}
		bookings = append(bookings, b)
	}

	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error iterating bookings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"bookings": bookings, "limit": limit, "offset": offset})
}

func (bc *BusinessPaymentController) GetBooking(c *gin.Context) {
	bookingIDStr := c.Param("booking_id")
	bookingID, err := uuid.Parse(bookingIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid booking_id"})
		return
	}

	ctx := c.Request.Context()
	var b Booking
	err = bc.DB.QueryRow(ctx, `SELECT id, customer_id, status FROM bookings WHERE id = $1`, bookingID).Scan(&b.ID, &b.CustomerID, &b.Status)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "booking not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query booking"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"booking": b})
}

type CreatePayoutRequest struct {
	Amount       float64 `json:"amount" binding:"required,gt=0"`
	TransferID   string  `json:"transfer_id" binding:"required"`
	TransferMode string  `json:"transfer_mode" binding:"required"`
	BeneDetails  struct {
		BankAccount string `json:"bank_account" binding:"required"`
		IFSC        string `json:"ifsc" binding:"required"`
		Name        string `json:"name" binding:"required"`
		Phone       string `json:"phone" binding:"required"`
		Email       string `json:"email"`
		VPA         string `json:"vpa"`
		Address1    string `json:"address1"`
	} `json:"bene_details" binding:"required"`
}

func (bc *BusinessPaymentController) CreatePayout(c *gin.Context) {
	if bc.PayoutClientID == "" || bc.PayoutClientSecret == "" {
		logger.ErrorLogger.Error("Cashfree payout credentials not configured")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cashfree payout credentials not configured"})
		return
	}

	var req CreatePayoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Invalid request payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	token, err := bc.getPayoutToken(c.Request.Context())
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get payout token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to authenticate with cashfree payouts"})
		return
	}

	payload := map[string]interface{}{
		"amount":       req.Amount,
		"transferId":   req.TransferID,
		"transferMode": req.TransferMode,
		"beneDetails":  req.BeneDetails,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize cashfree payload"})
		return
	}

	resp, err := bc.callPayout(c.Request.Context(), "POST", "/payout/v1/directTransfer", bytes.NewBuffer(jsonPayload), true, token)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree payout request failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree returned non-2xx", "status": resp.StatusCode, "body": string(b)})
		return
	}

	var cfResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid cashfree response"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"payout": cfResp})
}
