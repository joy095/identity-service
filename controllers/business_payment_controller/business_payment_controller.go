package business_payment_controller

import (
	"bytes"
	"context"
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
	DB           *pgxpool.Pool
	ClientID     string
	ClientSecret string
	APIVersion   string
	BaseURL      string
	HttpClient   *http.Client // Shared HTTP client for performance
}

// NewPaymentController creates a new payment controller
func NewPaymentController(db *pgxpool.Pool) (*PaymentController, error) {
	clientID := os.Getenv("CASHFREE_CLIENT_ID")
	clientSecret := os.Getenv("CASHFREE_CLIENT_SECRET")
	apiVersion := os.Getenv("CASHFREE_API_VERSION")

	if clientID == "" || clientSecret == "" || apiVersion == "" {
		return nil, fmt.Errorf("required Cashfree environment variables not set")
	}

	baseURL := os.Getenv("CASHFREE_BASE_URL")
	if baseURL == "" {
		baseURL = "https://sandbox.cashfree.com/pg" // Default to sandbox
	}

	pc := &PaymentController{
		DB:           db,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		APIVersion:   apiVersion,
		BaseURL:      baseURL,
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

// CreateOrderAndPayment creates a new payment order and optionally initiates payment
func (pc *PaymentController) CreateOrderAndPayment(c *gin.Context) {
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

	// get service
	service, err := service_models.GetServiceByIDModel(ctx, pc.DB, req.ServiceID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get service %s: %v", req.ServiceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get service"})
		return
	}

	EndTime := req.StartTime.Add(time.Duration(service.Duration) * time.Second)

	now := time.Now().UTC()
	if req.StartTime.Before(now) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Slot date/time cannot be in the past"})
		return
	}

	if req.Currency != "INR" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// check slot overlap
	hasOverlap, err := payment_models.HasBookingOverlap(ctx, pc.DB, req.ServiceID, req.StartTime, EndTime)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to check overlap for service %s: %v", req.ServiceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check availability"})
		return
	}
	if hasOverlap {
		c.JSON(http.StatusConflict, gin.H{"error": "This time slot is already booked by another user"})
		return
	}

	// validate UPI if provided
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

	// create Cashfree order
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

	// save to DB
	var dbOrderID uuid.UUID
	err = pc.DB.QueryRow(ctx,
		`INSERT INTO orders (order_id, customer_id, service_id, start_time, end_time, amount, currency, cf_order_id, payment_session_id, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
         RETURNING id`,
		cfOrderID, customerID, req.ServiceID, req.StartTime.UTC(), EndTime.UTC(), service.Price, req.Currency,
		cfOrderID, cfPaymentSessionID, OrderStatusPending,
	).Scan(&dbOrderID)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to insert order in DB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save order"})
		return
	}

	logger.InfoLogger.Infof("Order created: %s for customer: %s", cfOrderID, customerID)

	// initiate payment if provided
	if len(req.PaymentMethod) > 0 {
		paymentPayload := map[string]interface{}{
			"payment_session_id": cfPaymentSessionID,
			"payment_method":     req.PaymentMethod,
		}
		jsonPaymentPayload, _ := json.Marshal(paymentPayload)

		paymentResp, err := pc.makeRequest(ctx, "POST", "/orders/sessions", bytes.NewBuffer(jsonPaymentPayload))
		if err != nil {
			logger.ErrorLogger.Errorf("Cashfree payment initiation failed: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "payment gateway error"})
			return
		}
		defer paymentResp.Body.Close()
	}

	// send success response to client immediately
	c.JSON(http.StatusOK, gin.H{
		"order_id":           cfOrderID,
		"payment_session_id": cfPaymentSessionID,
		"status":             OrderStatusPending,
	})
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

	// Fetch refund status after creation
	refundStatusResp, err := pc.makeRequest(ctx, "GET", "/orders/"+orderID+"/refunds/"+refundID, nil)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch refund status for %s: %v", refundID, err)
	} else {
		defer refundStatusResp.Body.Close()
		if refundStatusResp.StatusCode == http.StatusOK {
			var refundStatusData map[string]interface{}
			if err := json.NewDecoder(refundStatusResp.Body).Decode(&refundStatusData); err == nil {
				refundStatus, _ := refundStatusData["refund_status"].(string)
				var newRefundStatus string
				var updateOrder bool
				switch refundStatus {
				case "SUCCESS":
					newRefundStatus = StatusRefundSuccess
					updateOrder = true
				case "FAILED":
					newRefundStatus = StatusRefundFailed
					updateOrder = false
				case "CANCELLED":
					newRefundStatus = StatusRefundReversed
					updateOrder = false
				default:
					newRefundStatus = StatusRefundPending
					updateOrder = false
				}

				tx, err := pc.DB.Begin(ctx)
				if err != nil {
					logger.ErrorLogger.Errorf("[TX_BEGIN_FAIL] Update refund status for %s: %v", refundID, err)
				} else {
					_, err = tx.Exec(ctx,
						`UPDATE refunds 
                         SET status = $1, updated_at = NOW()
                         WHERE refund_id = $2`,
						newRefundStatus, refundID)
					if err != nil {
						logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update refund status for %s: %v", refundID, err)
						tx.Rollback(ctx)
					} else {
						if updateOrder {
							_, err = tx.Exec(ctx,
								`UPDATE orders 
                                 SET status = $1, updated_at = NOW()
                                 WHERE order_id = $2 AND status = $3`,
								OrderStatusRefunded, orderID, OrderStatusPaid)
							if err != nil {
								logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update order for refund %s: %v", refundID, err)
								tx.Rollback(ctx)
							} else {
								tx.Commit(ctx)
								logger.InfoLogger.Infof("Refund %s updated to %s and order %s to REFUNDED via API poll", refundID, newRefundStatus, orderID)
							}
						} else {
							tx.Commit(ctx)
							logger.InfoLogger.Infof("Refund %s updated to %s via API poll", refundID, newRefundStatus)
						}
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"refund_id": refundID,
		"refund":    cfResp,
	})
}

// getOrderInternal retrieves and updates order (no refunds)
func (pc *PaymentController) getOrderInternal(c *gin.Context, orderID string) error {
	if orderID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "order_id required"})
		return nil
	}

	customerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		if err.Error() == "unauthorized" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return err
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
		Status           string    `db:"status"`
		CFPaymentID      *string   `db:"cf_payment_id"`
	}

	// fetch from DB
	err = pc.DB.QueryRow(ctx,
		`SELECT id, order_id, service_id, start_time, end_time, amount, payment_session_id, currency, created_at, status, cf_payment_id
         FROM orders 
         WHERE customer_id = $1 AND order_id = $2`,
		customerID, orderID).Scan(
		&order.ID, &order.OrderID, &order.ServiceID, &order.StartTime, &order.EndTime,
		&order.Amount, &order.PaymentSessionID, &order.Currency, &order.CreatedAt,
		&order.Status, &order.CFPaymentID,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "order not found"})
		} else {
			logger.ErrorLogger.Errorf("Failed to get order %s for customer %s: %v", orderID, customerID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		}
		return err
	}

	// poll status from Cashfree
	orderStatusResp, err := pc.makeRequest(ctx, "GET", "/orders/"+orderID, nil)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch order status for %s: %v", orderID, err)
	} else {
		defer orderStatusResp.Body.Close()
		if orderStatusResp.StatusCode == http.StatusOK {
			var orderStatusData map[string]interface{}
			if err := json.NewDecoder(orderStatusResp.Body).Decode(&orderStatusData); err == nil {
				orderStatus, _ := orderStatusData["order_status"].(string)
				cfPaymentID, _ := orderStatusData["cf_payment_id"].(string)

				var newOrderStatus string
				switch orderStatus {
				case "PAID":
					newOrderStatus = OrderStatusPaid
				case "TERMINATED", "FAILED":
					newOrderStatus = OrderStatusPending
				default:
					newOrderStatus = OrderStatusPending
				}

				if newOrderStatus != order.Status || (cfPaymentID != "" && (order.CFPaymentID == nil || *order.CFPaymentID != cfPaymentID)) {
					tx, err := pc.DB.Begin(ctx)
					if err != nil {
						logger.ErrorLogger.Errorf("[TX_BEGIN_FAIL] Update order status for %s: %v", orderID, err)
					} else {
						query := `UPDATE orders 
                                  SET status = $1, updated_at = NOW()`
						args := []interface{}{newOrderStatus, orderID, OrderStatusPending}
						if cfPaymentID != "" {
							query += `, cf_payment_id = $4`
							args = append(args, cfPaymentID)
						}
						query += ` WHERE order_id = $2 AND status = $3`

						result, err := tx.Exec(ctx, query, args...)
						if err != nil {
							logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update order status for %s: %v", orderID, err)
							tx.Rollback(ctx)
						} else {
							if rowsAffected := result.RowsAffected(); rowsAffected > 0 {
								_ = tx.Commit(ctx)
								logger.InfoLogger.Infof("Order %s updated to %s via GetOrder API poll", orderID, newOrderStatus)
								order.Status = newOrderStatus
								if cfPaymentID != "" {
									order.CFPaymentID = &cfPaymentID
								}
							} else {
								_ = tx.Rollback(ctx)
							}
						}
					}
				}
			}
		}
	}

	// return response
	c.JSON(http.StatusOK, gin.H{
		"order_id":           order.OrderID,
		"service_id":         order.ServiceID,
		"start_time":         order.StartTime,
		"end_time":           order.EndTime,
		"amount":             order.Amount,
		"currency":           order.Currency,
		"created_at":         order.CreatedAt,
		"payment_session_id": order.PaymentSessionID,
		"status":             order.Status,
		"cf_payment_id":      order.CFPaymentID,
		"payment": gin.H{
			"order_amount":   order.Amount,
			"order_currency": order.Currency,
		},
	})

	return nil
}

// Public handler: order_id from params
func (pc *PaymentController) GetOrder(c *gin.Context) {
	orderID := c.Param("order_id")
	pc.getOrderInternal(c, orderID)
}

// Reuse: pass orderID directly
func (pc *PaymentController) GetOrderByID(c *gin.Context, orderID string) {
	pc.getOrderInternal(c, orderID)
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

// CreateOrderRequest structure
type CreateOrderRequest struct {
	Currency      string                 `json:"currency" binding:"required,len=3"`
	ServiceID     uuid.UUID              `json:"service_id" binding:"required"`
	StartTime     time.Time              `json:"start_time" binding:"required"`
	UpiID         string                 `json:"upi_id"`
	PaymentMethod map[string]interface{} `json:"payment_method"`
}

// CreateRefundRequest structure
type CreateRefundRequest struct {
	Amount float64 `json:"amount" binding:"required,gt=0"`
	Note   string  `json:"note"`
}
