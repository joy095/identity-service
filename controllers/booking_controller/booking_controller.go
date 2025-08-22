package booking_controller

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BookingController holds dependencies for business-related operations.
type BookingController struct {
	DB *pgxpool.Pool
}

// NewBookingController creates a new instance of BookingController.
func NewBookingController(db *pgxpool.Pool) *BookingController {
	return &BookingController{
		DB: db,
	}
}

type CreateBookingRequest struct {
	CustomerPhone string  `json:"customer_phone" binding:"required"`
	CustomerId    string  `json:"customer_id" binding:"required,uuid4"`
	OrderCurrency string  `json:"order_currency" binding:"required,len=3"`
	OrderAmount   float64 `json:"order_amount" binding:"required,gt=0"`
}

func (bc *BookingController) Book(c *gin.Context) {
	var req CreateBookingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	clientID := os.Getenv("CASHFREE_CLIENT_ID")
	clientSecret := os.Getenv("CASHFREE_CLIENT_SECRET")
	apiVersion := os.Getenv("X_API_VERSION")
	baseURL := "https://sandbox.cashfree.com/pg/orders"

	if clientID == "" || clientSecret == "" || apiVersion == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cashfree credentials not configured"})
		return
	}

	// 1. Insert booking (pending)
	bookingID := uuid.New()
	ctx := c.Request.Context()
	if _, err := bc.DB.Exec(ctx, `INSERT INTO bookings (id, customer_id, status) VALUES ($1, $2, 'pending')`,
		bookingID, req.CustomerId); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create booking"})
		return
	}

	// 2. Prepare Cashfree order payload
	orderID := "order_" + uuid.New().String()
	payload := map[string]interface{}{
		"order_id":       orderID,
		"order_amount":   req.OrderAmount,
		"order_currency": req.OrderCurrency,
		"customer_details": map[string]string{
			"customer_id":    req.CustomerId,
			"customer_phone": req.CustomerPhone,
		},
		"order_meta": map[string]string{
			"return_url": "https://yourapp.com/payment/callback?order_id=" + orderID,
		},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize cashfree payload"})
		return
	}

	// 3. Call Cashfree API
	reqCF, err := http.NewRequestWithContext(c.Request.Context(), "POST", baseURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to construct cashfree request"})
		return
	}
	reqCF.Header.Set("Accept", "application/json")
	reqCF.Header.Set("x-client-id", clientID)
	reqCF.Header.Set("x-client-secret", clientSecret)
	reqCF.Header.Set("x-api-version", apiVersion)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(reqCF)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree request failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap at 1MB
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree returned non-2xx", "status": resp.StatusCode, "body": string(b)})
		return
	}
	var cfResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid cashfree response"})
		return
	}

	// 4. Save payment
	if _, err := bc.DB.Exec(ctx, `INSERT INTO payments (id, booking_id, order_id, amount, currency, status) 
                                VALUES ($1, $2, $3, $4, $5, 'pending')`,
		uuid.New(), bookingID, orderID, req.OrderAmount, req.OrderCurrency); err != nil {
		// Best-effort: mark booking as failed so it doesn't remain stuck in 'pending'
		_, _ = bc.DB.Exec(ctx, `UPDATE bookings SET status = 'failed' WHERE id = $1`, bookingID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create payment"})
		return
	}

	// 5. Respond
	c.JSON(http.StatusOK, gin.H{
		"booking_id": bookingID,
		"order_id":   orderID,
		"payment":    cfResp,
	})
}
