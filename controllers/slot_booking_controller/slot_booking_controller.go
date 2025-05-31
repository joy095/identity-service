package slot_booking_controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// RazorpayWebhookPayload represents the structure of a Razorpay webhook payload.
type RazorpayWebhookPayload struct {
	Entity    string   `json:"entity"` // "event"
	AccountID string   `json:"account_id"`
	Event     string   `json:"event"`
	Contains  []string `json:"contains"`
	Payload   struct {
		Payment *struct {
			Entity struct {
				ID               string                 `json:"id"`
				OrderID          string                 `json:"order_id"`
				Amount           int                    `json:"amount"` // in paise
				Currency         string                 `json:"currency"`
				Status           string                 `json:"status"` // "captured", "failed", etc.
				Method           string                 `json:"method"`
				Captured         bool                   `json:"captured"`
				CreatedAt        int64                  `json:"created_at"` // Unix timestamp
				Notes            map[string]interface{} `json:"notes"`
				ErrorDescription *string                `json:"error_description"`
			} `json:"entity"`
		} `json:"payment"`
		// Other entities like Order, Refund, etc. can be here
	} `json:"payload"`
	CreatedAt int64 `json:"created_at"` // Unix timestamp
}

// --- Constants for Redis Keys ---
const (
	RedisSlotBookingPrefix = "slot_reservation:"
	RedisSlotExpiry        = 10 * time.Minute
)

// SlotBookingService handles the business logic for slot bookings.
type SlotBookingService struct {
	DB                    *pgxpool.Pool
	RedisClient           *redis.Client
	RazorpayClient        clients.RazorpayClientWrapper
	RazorpayWebhookSecret string // Your Razorpay webhook secret
}

// NewSlotBookingService creates a new SlotBookingService.
func NewSlotBookingService(db *pgxpool.Pool, rdb *redis.Client, rzpClient clients.RazorpayClientWrapper, rzpWebhookSecret string) *SlotBookingService {
	return &SlotBookingService{
		DB:                    db,
		RedisClient:           rdb,
		RazorpayClient:        rzpClient,
		RazorpayWebhookSecret: rzpWebhookSecret,
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
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	logger.InfoLogger.Infof("Initiating slot booking for slot %s, service %s, customer %s", req.SlotID, req.ServiceID, req.CustomerID)

	// 1. Check and Reserve Slot in Redis
	err := s.CheckAndReserveSlot(ctx, req)
	if err != nil {
		logger.WarnLogger.Warnf("Slot reservation failed for slot %s: %v", req.SlotID, err)
		return nil, "", fmt.Errorf("slot reservation failed: %w", err)
	}

	defer s.ReleaseSlotReservation(ctx, req.SlotID, req.CustomerID) // Release upon function exit

	// 2. Get Service Details to determine price
	service, err := service_models.GetServiceByID(s.DB, req.ServiceID)
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
		return nil, "", fmt.Errorf("failed to create pending booking: %w", err)
	}
	logger.InfoLogger.Infof("Pending booking %s created for slot %s", createdBooking.ID, req.SlotID)

	// 4. Initiate Razorpay Payment Order
	amountInPaise := int(service.Price * 100)
	currency := "INR" // Assuming INR for India

	orderData := map[string]interface{}{
		"amount":   amountInPaise,
		"currency": currency,
		"receipt":  createdBooking.ID.String(),
		"notes": map[string]interface{}{
			"booking_id":  createdBooking.ID.String(),
			"customer_id": createdBooking.CustomerID.String(),
			"slot_id":     createdBooking.SlotID.String(),
			"service_id":  createdBooking.ServiceID.String(),
		},
	}

	rzpOrder, err := s.RazorpayClient.CreateOrder(orderData)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create Razorpay order for booking %s: %v", createdBooking.ID, err)
		_ = booking_models.UpdateBookingStatus(ctx, s.DB, createdBooking.ID, shared_models.BookingStatusFailed)
		return nil, "", fmt.Errorf("failed to initiate payment: %w", err)
	}

	razorpayOrderID, ok := rzpOrder["id"].(string)
	if !ok || razorpayOrderID == "" {
		logger.ErrorLogger.Errorf("Razorpay order ID not found in response for booking %s", createdBooking.ID)
		_ = booking_models.UpdateBookingStatus(ctx, s.DB, createdBooking.ID, shared_models.BookingStatusFailed)
		return nil, "", fmt.Errorf("invalid Razorpay order response")
	}

	logger.InfoLogger.Infof("Razorpay order %s created for booking %s", razorpayOrderID, createdBooking.ID)

	// 5. Save Payment Transaction details (initial status)
	paymentTx, err := payment_transaction_models.NewPaymentTransaction(createdBooking.ID, razorpayOrderID, service.Price, currency)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create payment transaction object for booking %s: %v", createdBooking.ID, err)
		_ = booking_models.UpdateBookingStatus(ctx, s.DB, createdBooking.ID, shared_models.BookingStatusFailed)
		return nil, "", fmt.Errorf("internal error setting up payment record: %w", err)
	}

	_, err = payment_transaction_models.CreatePaymentTransaction(ctx, s.DB, paymentTx)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to save initial payment transaction for booking %s: %v", createdBooking.ID, err)
		_ = booking_models.UpdateBookingStatus(ctx, s.DB, createdBooking.ID, shared_models.BookingStatusFailed)
		return nil, "", fmt.Errorf("failed to record payment attempt: %w", err)
	}

	return createdBooking, razorpayOrderID, nil
}

// HandleRazorpayWebhook processes payment confirmation/failure from Razorpay webhooks.
func (s *SlotBookingService) HandleRazorpayWebhook(ctx context.Context, signature, body string) error {
	// Verify webhook signature (CRITICAL for security)
	if !s.RazorpayClient.VerifyPaymentSignature(signature, body, s.RazorpayWebhookSecret) {
		logger.ErrorLogger.Errorf("Webhook signature verification failed.")
		return fmt.Errorf("invalid webhook signature")
	}
	logger.InfoLogger.Info("Razorpay webhook signature verified successfully.")

	var payload RazorpayWebhookPayload
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse Razorpay webhook payload: %v", err)
		return fmt.Errorf("invalid webhook payload")
	}

	if payload.Event != "payment.captured" && payload.Event != "payment.failed" {
		logger.InfoLogger.Infof("Unhandled Razorpay event type: %s", payload.Event)
		return nil
	}

	paymentEntity := payload.Payload.Payment.Entity
	if paymentEntity.OrderID == "" {
		logger.ErrorLogger.Error("Razorpay Order ID not found in webhook payload")
		return fmt.Errorf("missing Razorpay Order ID")
	}

	// Fetch existing transaction by Razorpay Order ID
	paymentTx, err := payment_transaction_models.GetPaymentTransactionByRazorpayOrderID(ctx, s.DB, paymentEntity.OrderID)
	if err != nil {
		// If transaction not found, it might be a race condition or direct webhook without initial booking.
		// Re-create transaction and handle.
		if errors.Is(err, fmt.Errorf("payment transaction not found")) {
			logger.WarnLogger.Warnf("Payment transaction for Razorpay Order ID %s not found. Attempting to create new from webhook.", paymentEntity.OrderID)
			bookingIDStr, ok := paymentEntity.Notes["booking_id"].(string)
			if !ok || bookingIDStr == "" {
				logger.ErrorLogger.Errorf("Booking ID not found in Razorpay payment notes for order %s. Cannot create payment transaction.", paymentEntity.OrderID)
				return fmt.Errorf("missing booking ID in payment notes")
			}
			bookingID, parseErr := uuid.Parse(bookingIDStr)
			if parseErr != nil {
				logger.ErrorLogger.Errorf("Invalid booking ID format from Razorpay notes '%s': %v", bookingIDStr, parseErr)
				return fmt.Errorf("invalid booking ID format in notes")
			}

			paymentTx, err = payment_transaction_models.NewPaymentTransaction(bookingID, paymentEntity.OrderID, float64(paymentEntity.Amount)/100, paymentEntity.Currency)
			if err != nil {
				logger.ErrorLogger.Errorf("Failed to create new payment transaction object for webhook: %v", err)
				return fmt.Errorf("internal error handling payment: %w", err)
			}
			_, err = payment_transaction_models.CreatePaymentTransaction(ctx, s.DB, paymentTx)
			if err != nil {
				logger.ErrorLogger.Errorf("Failed to save new payment transaction from webhook: %v", err)
				return fmt.Errorf("failed to record payment transaction: %w", err)
			}
		} else {
			logger.ErrorLogger.Errorf("Database error fetching payment transaction for order %s: %v", paymentEntity.OrderID, err)
			return fmt.Errorf("database error processing webhook: %w", err)
		}
	} else {
		// Idempotency check: If the transaction is already captured/failed, skip processing.
		if paymentTx.Status == "captured" || paymentTx.Status == "failed" {
			logger.InfoLogger.Infof("Webhook for order %s already processed with status %s. Skipping.", paymentEntity.OrderID, paymentTx.Status)
			return nil
		}
	}

	paymentTx.RazorpayPaymentID = paymentEntity.ID
	paymentTx.Status = paymentEntity.Status
	paymentTx.Amount = float64(paymentEntity.Amount) / 100
	paymentTx.Currency = paymentEntity.Currency
	paymentTx.PaymentMethod = paymentEntity.Method
	paymentTx.ErrorDescription = paymentEntity.ErrorDescription

	if paymentEntity.Captured {
		capturedAt := time.Unix(paymentEntity.CreatedAt, 0)
		paymentTx.CapturedAt = &capturedAt
		paymentTx.Status = "captured"
	}

	err = payment_transaction_models.UpdatePaymentTransaction(ctx, s.DB, paymentTx)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update payment transaction %s in webhook: %v", paymentTx.ID, err)
		return fmt.Errorf("failed to update payment record: %w", err)
	}

	bookingID := paymentTx.BookingID // Use bookingID from the paymentTx
	slotIDStr, ok := paymentEntity.Notes["slot_id"].(string)
	var slotID uuid.UUID
	if ok && slotIDStr != "" {
		slotID, err = uuid.Parse(slotIDStr)
		if err != nil {
			logger.ErrorLogger.Errorf("Invalid slot ID format from Razorpay notes '%s': %v", slotIDStr, err)
		}
	}
	customerIDStr, ok := paymentEntity.Notes["customer_id"].(string)
	var customerID uuid.UUID
	if ok && customerIDStr != "" {
		customerID, err = uuid.Parse(customerIDStr)
		if err != nil {
			logger.ErrorLogger.Errorf("Invalid customer ID format from Razorpay notes '%s': %v", customerIDStr, err)
		}
	}

	// --- Process Booking Status Update based on Payment Status ---
	if payload.Event == "payment.captured" && paymentEntity.Captured {
		logger.InfoLogger.Infof("Payment captured for booking %s (Razorpay Order: %s)", bookingID, paymentEntity.OrderID)

		// 1. Update Booking Status to Confirmed
		err = booking_models.UpdateBookingStatus(ctx, s.DB, bookingID, shared_models.BookingStatusConfirmed)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to update booking %s to confirmed: %v", bookingID, err)
			return fmt.Errorf("failed to confirm booking: %w", err)
		}

		// 2. Mark the Schedule Slot as Unavailable
		if slotID != uuid.Nil {
			err = schedule_slot_models.UpdateScheduleSlotAvailability(ctx, s.DB, slotID, false)
			if err != nil {
				logger.ErrorLogger.Errorf("Failed to mark slot %s as unavailable after booking %s: %v", slotID, bookingID, err)
				return fmt.Errorf("failed to mark slot unavailable, manual intervention may be required: %w", err)
			}
		}

		// 3. Release Redis Reservation (if customerID was retrieved)
		if slotID != uuid.Nil && customerID != uuid.Nil {
			s.ReleaseSlotReservation(ctx, slotID, customerID)
		}

	} else if payload.Event == "payment.failed" {
		logger.WarnLogger.Warnf("Payment failed for booking %s (Razorpay Order: %s), error: %s",
			bookingID, paymentEntity.OrderID, *paymentEntity.ErrorDescription)

		// Update Booking Status to Failed
		err = booking_models.UpdateBookingStatus(ctx, s.DB, bookingID, shared_models.BookingStatusFailed)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to update booking %s to failed: %v", bookingID, err)
			return fmt.Errorf("failed to mark booking as failed: %w", err)
		}

		// Release Redis Reservation (if it still exists and customerID was retrieved)
		if slotID != uuid.Nil && customerID != uuid.Nil {
			s.ReleaseSlotReservation(ctx, slotID, customerID)
		}
	}

	logger.InfoLogger.Infof("Successfully processed Razorpay webhook for event %s, booking %s", payload.Event, bookingID)
	return nil
}
