package slot_booking_controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/joy095/identity/clients" // Import the new clients package
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/booking_models"
	"github.com/joy095/identity/models/payment_transaction_models"
	"github.com/joy095/identity/models/schedule_slot_models" // Import the new models package
	"github.com/joy095/identity/models/service_models"
	"github.com/joy095/identity/models/shared_models"
)

// SlotBookingRequest represents the data required to book a slot.
type SlotBookingRequest struct {
	BusinessID uuid.UUID `json:"business_id"`
	ServiceID  uuid.UUID `json:"service_id"`
	SlotID     uuid.UUID `json:"slot_id"`
	CustomerID uuid.UUID `json:"customer_id"`
}

// CashfreeWebhookPayload represents the structure of a Cashfree webhook payload.
type CashfreeWebhookPayload struct {
	Type string `json:"type"` // "PAYMENT_SUCCESS_WEBHOOK", "PAYMENT_FAILED_WEBHOOK", etc.
	Data struct {
		Order struct {
			OrderID       string  `json:"order_id"`
			OrderAmount   float64 `json:"order_amount"`
			OrderCurrency string  `json:"order_currency"`
			OrderStatus   string  `json:"order_status"` // "PAID", "ACTIVE", "EXPIRED", etc.
		} `json:"order"`
		Payment struct {
			CFPaymentID     string                 `json:"cf_payment_id"`
			PaymentStatus   string                 `json:"payment_status"`   // "SUCCESS", "FAILED", etc.
			PaymentAmount   float64                `json:"payment_amount"`
			PaymentCurrency string                 `json:"payment_currency"`
			PaymentMessage  string                 `json:"payment_message"`
			PaymentTime     string                 `json:"payment_time"`     // ISO timestamp
			PaymentMethod   map[string]interface{} `json:"payment_method"`
			ErrorDetails    map[string]interface{} `json:"error_details,omitempty"`
		} `json:"payment"`
		CustomerDetails map[string]interface{} `json:"customer_details"`
	} `json:"data"`
	EventTime string `json:"event_time"` // ISO timestamp
}

// --- Constants for Redis Keys ---
const (
	RedisSlotBookingPrefix = "slot_reservation:"
	RedisSlotExpiry        = 10 * time.Minute
)

// SlotBookingService handles the business logic for slot bookings.
type SlotBookingService struct {
	DB                     *pgxpool.Pool
	RedisClient            *redis.Client
	CashfreeClient         clients.CashfreeClientWrapper
	CashfreeWebhookSecret  string // Your Cashfree webhook secret
}

// NewSlotBookingService creates a new SlotBookingService.
func NewSlotBookingService(db *pgxpool.Pool, rdb *redis.Client, cfClient clients.CashfreeClientWrapper, cfWebhookSecret string) *SlotBookingService {
	return &SlotBookingService{
		DB:                     db,
		RedisClient:            rdb,
		CashfreeClient:         cfClient,
		CashfreeWebhookSecret:  cfWebhookSecret,
	}
}

// --- Helper Functions ---

// getRedisReservationKey generates a unique key for Redis reservation.
func getRedisReservationKey(slotID, customerID uuid.UUID) string {
	return fmt.Sprintf("%s%s:%s", RedisSlotBookingPrefix, slotID.String(), customerID.String())
}

// CheckAndReserveSlot checks availability and reserves a slot in Redis.
func (s *SlotBookingService) CheckAndReserveSlot(ctx context.Context, req *SlotBookingRequest) error {
	logger.InfoLogger.Infof("Attempting to reserve slot %s for customer %s", req.SlotID, req.CustomerID)

	// 1. Check if the slot exists and is available in the database
	slot, err := schedule_slot_models.GetScheduleSlotByID(ctx, s.DB, req.SlotID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch slot %s: %v", req.SlotID, err)
		return fmt.Errorf("slot not found or database error: %w", err)
	}

	if !slot.IsAvailable {
		return fmt.Errorf("slot %s is already booked or unavailable", req.SlotID)
	}

	// 2. Check if the slot is temporarily reserved in Redis
	redisKey := getRedisReservationKey(req.SlotID, req.CustomerID)
	val, err := s.RedisClient.Get(ctx, redisKey).Result()
	if err == nil && val != "" {
		// Slot is already reserved by this customer, allowing to proceed
		logger.InfoLogger.Infof("Slot %s already reserved by customer %s in Redis. Proceeding.", req.SlotID, req.CustomerID)
		return nil
	} else if err != nil && !errors.Is(err, redis.Nil) {
		logger.ErrorLogger.Errorf("Redis error checking reservation for slot %s: %v", req.SlotID, err)
		return fmt.Errorf("failed to check slot reservation: %w", err)
	}

	// Attempt to reserve the slot in Redis
	reservationData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal reservation data: %w", err)
	}

	set, err := s.RedisClient.SetNX(ctx, redisKey, reservationData, RedisSlotExpiry).Result()
	if err != nil {
		logger.ErrorLogger.Errorf("Redis error setting reservation for slot %s: %v", req.SlotID, err)
		return fmt.Errorf("failed to reserve slot in Redis: %w", err)
	}
	if !set {
		return fmt.Errorf("slot %s was just reserved by another request. Please try another slot or refresh.", req.SlotID)
	}

	logger.InfoLogger.Infof("Slot %s successfully reserved in Redis for customer %s for %v", req.SlotID, req.CustomerID, RedisSlotExpiry)

	return nil
}

// ReleaseSlotReservation releases a slot reservation from Redis.
func (s *SlotBookingService) ReleaseSlotReservation(ctx context.Context, slotID, customerID uuid.UUID) {
	redisKey := getRedisReservationKey(slotID, customerID)
	if err := s.RedisClient.Del(ctx, redisKey).Err(); err != nil {
		logger.ErrorLogger.Errorf("Failed to release Redis reservation for slot %s, customer %s: %v", slotID, customerID, err)
	} else {
		logger.InfoLogger.Infof("Redis reservation for slot %s, customer %s released.", slotID, customerID)
	}
}

// BookSlot handles the entire slot booking workflow.
// It returns the created Booking object and the Razorpay Order ID for the frontend.
func (s *SlotBookingService) BookSlot(ctx context.Context, req *SlotBookingRequest) (*booking_models.Booking, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	logger.InfoLogger.Infof("Initiating slot booking for slot %s, service %s, customer %s", req.SlotID, req.ServiceID, req.CustomerID)

	if req.BusinessID == uuid.Nil || req.ServiceID == uuid.Nil ||
		req.SlotID == uuid.Nil || req.CustomerID == uuid.Nil {
		return nil, "", fmt.Errorf("invalid input: all IDs are required")
	}

	// 1. Check and Reserve Slot in Redis
	err := s.CheckAndReserveSlot(ctx, req)
	if err != nil {
		logger.WarnLogger.Warnf("Slot reservation failed for slot %s: %v", req.SlotID, err)
		return nil, "", fmt.Errorf("slot reservation failed: %w", err)
	}

	// 2. Get Service Details to determine price
	service, err := service_models.GetServiceByIDModel(ctx, s.DB, req.ServiceID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch service %s: %v", req.ServiceID, err)
		return nil, "", fmt.Errorf("invalid service selected: %w", err)
	}

	if !service.IsActive {
		return nil, "", fmt.Errorf("service '%s' is not active", service.Name)
	}

	// 3. Create a Pending Booking in DB
	newBooking, err := booking_models.NewBooking(req.BusinessID, req.ServiceID, req.SlotID, req.CustomerID, shared_models.BookingStatusPending)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create new booking object: %v", err)
		return nil, "", fmt.Errorf("internal error creating booking: %w", err)
	}

	createdBooking, err := booking_models.CreateBooking(ctx, s.DB, newBooking)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to save pending booking to DB: %v", err)
		s.ReleaseSlotReservation(ctx, req.SlotID, req.CustomerID)
		return nil, "", fmt.Errorf("failed to create pending booking: %w", err)
	}
	logger.InfoLogger.Infof("Pending booking %s created for slot %s", createdBooking.ID, req.SlotID)

	// 4. Initiate Cashfree Payment Order
	amount := float64(service.Price) // Cashfree uses actual amount, not paise
	if service.Price <= 0 {
		return nil, "", fmt.Errorf("invalid service price: %d", service.Price)
	}

	currency := os.Getenv("PAYMENT_CURRENCY")
	if currency == "" {
		currency = "INR" // Default to INR
	}
	supportedCurrencies := map[string]bool{"INR": true, "USD": true, "EUR": true}
	if !supportedCurrencies[currency] {
		logger.WarnLogger.Warnf("Unsupported currency %s, defaulting to INR", currency)
		currency = "INR"
	}

	// Prepare customer details (required for Cashfree)
	customerDetails := map[string]interface{}{
		"customer_id":    createdBooking.CustomerID.String(),
		"customer_name":  "Customer", // You might want to fetch actual customer details
		"customer_email": "customer@example.com", // Replace with actual customer email
		"customer_phone": "9999999999", // Replace with actual customer phone
	}

	orderData := map[string]interface{}{
		"order_id":         createdBooking.ID.String(),
		"order_amount":     amount,
		"order_currency":   currency,
		"customer_details": customerDetails,
		"order_meta": map[string]interface{}{
			"booking_id":  createdBooking.ID.String(),
			"customer_id": createdBooking.CustomerID.String(),
			"slot_id":     createdBooking.SlotID.String(),
			"service_id":  createdBooking.ServiceID.String(),
		},
		"order_note": fmt.Sprintf("Payment for booking %s", createdBooking.ID.String()),
	}

	cfOrder, err := s.CashfreeClient.CreateOrder(orderData)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create Cashfree order for booking %s: %v", createdBooking.ID, err)
		if err := booking_models.UpdateBookingStatus(ctx, s.DB, createdBooking.ID, shared_models.BookingStatusFailed); err != nil {
			logger.ErrorLogger.Errorf("Critical: Failed to update booking %s to failed status: %v", createdBooking.ID, err)
		}
		return nil, "", fmt.Errorf("failed to initiate payment: %w", err)
	}

	cashfreeOrderID, ok := cfOrder["cf_order_id"].(string)
	if !ok || cashfreeOrderID == "" {
		logger.ErrorLogger.Errorf("Cashfree order ID not found in response for booking %s", createdBooking.ID)
		_ = booking_models.UpdateBookingStatus(ctx, s.DB, createdBooking.ID, shared_models.BookingStatusFailed)
		return nil, "", fmt.Errorf("invalid Cashfree order response")
	}

	paymentSessionID, _ := cfOrder["payment_session_id"].(string)
	logger.InfoLogger.Infof("Cashfree order %s created for booking %s with payment session %s", cashfreeOrderID, createdBooking.ID, paymentSessionID)

	// 5. Save Payment Transaction details (initial status)
	paymentTx, err := payment_transaction_models.NewPaymentTransaction(createdBooking.ID, cashfreeOrderID, paymentSessionID, service.Price, currency)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create payment transaction object for booking %s: %v", createdBooking.ID, err)
		_ = booking_models.UpdateBookingStatus(ctx, s.DB, createdBooking.ID, shared_models.BookingStatusFailed)
		return nil, "", fmt.Errorf("internal error setting up payment record: %w", err)
	}

	_, err = payment_transaction_models.CreatePaymentTransaction(ctx, s.DB, paymentTx)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to save initial payment transaction for booking %s: %v", createdBooking.ID, err)
		if err := booking_models.UpdateBookingStatus(ctx, s.DB, createdBooking.ID, shared_models.BookingStatusFailed); err != nil {
			logger.ErrorLogger.Errorf("Failed to update booking %s to failed status: %v", createdBooking.ID, err)
		}

		return nil, "", fmt.Errorf("failed to record payment attempt: %w", err)
	}

	return createdBooking, paymentSessionID, nil
}

// HandleCashfreeWebhook processes payment confirmation/failure from Cashfree webhooks.
func (s *SlotBookingService) HandleCashfreeWebhook(ctx context.Context, signature, body string) error {
	// Verify webhook signature (CRITICAL for security)
	if !s.CashfreeClient.VerifyWebhookSignature(signature, body) {
		logger.ErrorLogger.Errorf("Cashfree webhook signature verification failed.")
		return fmt.Errorf("invalid webhook signature")
	}
	logger.InfoLogger.Info("Cashfree webhook signature verified successfully.")

	var payload CashfreeWebhookPayload
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse Cashfree webhook payload: %v", err)
		return fmt.Errorf("invalid webhook payload")
	}

	if payload.Type != "PAYMENT_SUCCESS_WEBHOOK" && payload.Type != "PAYMENT_FAILED_WEBHOOK" {
		logger.InfoLogger.Infof("Unhandled Cashfree event type: %s", payload.Type)
		return nil
	}

	orderID := payload.Data.Order.OrderID
	if orderID == "" {
		logger.ErrorLogger.Error("Cashfree Order ID not found in webhook payload")
		return fmt.Errorf("missing Cashfree Order ID")
	}

	// Parse booking ID from order ID (since we use booking ID as order ID)
	bookingID, err := uuid.Parse(orderID)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid booking ID format from order ID '%s': %v", orderID, err)
		return fmt.Errorf("invalid order ID format")
	}

	// Fetch existing transaction by Cashfree Order ID
	paymentTx, err := payment_transaction_models.GetPaymentTransactionByCashfreeOrderID(ctx, s.DB, orderID)
	if err != nil {
		logger.ErrorLogger.Errorf("Payment transaction for Cashfree Order ID %s not found: %v", orderID, err)
		return fmt.Errorf("payment transaction not found: %w", err)
	}

	// Idempotency check: If the transaction is already processed, skip processing.
	if paymentTx.Status == "PAID" || paymentTx.Status == "CANCELLED" {
		logger.InfoLogger.Infof("Webhook for order %s already processed with status %s. Skipping.", orderID, paymentTx.Status)
		return nil
	}

	// Update payment transaction with webhook data
	paymentTx.CashfreePaymentID = payload.Data.Payment.CFPaymentID
	paymentTx.Status = payload.Data.Order.OrderStatus

	// Validate amount matches original transaction
	if payload.Data.Order.OrderAmount != float64(paymentTx.Amount) {
		logger.ErrorLogger.Errorf("Amount mismatch in webhook: expected %f, got %f", float64(paymentTx.Amount), payload.Data.Order.OrderAmount)
		return fmt.Errorf("payment amount mismatch")
	}

	// Extract payment method
	if methodType, ok := payload.Data.Payment.PaymentMethod["type"].(string); ok {
		paymentTx.PaymentMethod = methodType
	}

	// Handle error details if payment failed
	if payload.Type == "PAYMENT_FAILED_WEBHOOK" {
		if errorMsg, ok := payload.Data.Payment.ErrorDetails["error_message"].(string); ok {
			paymentTx.ErrorDescription = &errorMsg
		}
	}

	// Set captured time for successful payments
	if payload.Type == "PAYMENT_SUCCESS_WEBHOOK" && payload.Data.Payment.PaymentTime != "" {
		if capturedAt, parseErr := time.Parse(time.RFC3339, payload.Data.Payment.PaymentTime); parseErr == nil {
			paymentTx.CapturedAt = &capturedAt
		}
		paymentTx.Status = "PAID"
	}

	err = payment_transaction_models.UpdatePaymentTransaction(ctx, s.DB, paymentTx)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update payment transaction %s in webhook: %v", paymentTx.ID, err)
		return fmt.Errorf("failed to update payment record: %w", err)
	}

	// Process Booking Status Update based on Payment Status
	if payload.Type == "PAYMENT_SUCCESS_WEBHOOK" {
		logger.InfoLogger.Infof("Payment successful for booking %s (Cashfree Order: %s)", bookingID, orderID)

		// 1. Update Booking Status to Confirmed
		err = booking_models.UpdateBookingStatus(ctx, s.DB, bookingID, shared_models.BookingStatusConfirmed)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to update booking %s to confirmed: %v", bookingID, err)
			return fmt.Errorf("failed to confirm booking: %w", err)
		}

		// 2. Get booking details to mark slot as unavailable
		booking, err := booking_models.GetBookingByID(ctx, s.DB, bookingID)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to fetch booking %s: %v", bookingID, err)
		} else {
			// Mark the Schedule Slot as Unavailable
			err = schedule_slot_models.UpdateScheduleSlotAvailability(ctx, s.DB, booking.SlotID, false)
			if err != nil {
				logger.ErrorLogger.Errorf("Failed to mark slot %s as unavailable after booking %s: %v", booking.SlotID, bookingID, err)
				return fmt.Errorf("failed to mark slot unavailable: %w", err)
			}

			// 3. Release Redis Reservation
			s.ReleaseSlotReservation(ctx, booking.SlotID, booking.CustomerID)
		}

	} else if payload.Type == "PAYMENT_FAILED_WEBHOOK" {
		errorDesc := payload.Data.Payment.PaymentMessage
		if errorDesc == "" {
			errorDesc = "unknown error"
		}
		logger.WarnLogger.Warnf("Payment failed for booking %s (Cashfree Order: %s), error: %s",
			bookingID, orderID, errorDesc)

		// Update Booking Status to Failed
		err = booking_models.UpdateBookingStatus(ctx, s.DB, bookingID, shared_models.BookingStatusFailed)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to update booking %s to failed: %v", bookingID, err)
			return fmt.Errorf("failed to mark booking as failed: %w", err)
		}

		// Release Redis Reservation
		booking, err := booking_models.GetBookingByID(ctx, s.DB, bookingID)
		if err == nil {
			s.ReleaseSlotReservation(ctx, booking.SlotID, booking.CustomerID)
		}
	}

	logger.InfoLogger.Infof("Successfully processed Cashfree webhook for event %s, booking %s", payload.Type, bookingID)
	return nil
}
