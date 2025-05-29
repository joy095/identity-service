package models

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
)

// PaymentTransaction represents a record of a payment transaction.
type PaymentTransaction struct {
	ID                uuid.UUID  `json:"id"`
	BookingID         uuid.UUID  `json:"booking_id"`
	RazorpayOrderID   string     `json:"razorpay_order_id"`
	RazorpayPaymentID string     `json:"razorpay_payment_id"`
	Amount            float64    `json:"amount"`
	Currency          string     `json:"currency"`
	Status            string     `json:"status"`      // e.g., "created", "authorized", "captured", "failed"
	CapturedAt        *time.Time `json:"captured_at"` // Nullable timestamp
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	PaymentMethod     string     `json:"payment_method"`    // e.g., "card", "upi", "netbanking"
	ErrorDescription  *string    `json:"error_description"` // Nullable error message
}

// NewPaymentTransaction creates a new PaymentTransaction struct.
func NewPaymentTransaction(bookingID uuid.UUID, rzpOrderID string, amount float64, currency string) (*PaymentTransaction, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID for payment transaction: %w", err)
	}
	now := time.Now()
	return &PaymentTransaction{
		ID:              id,
		BookingID:       bookingID,
		RazorpayOrderID: rzpOrderID,
		Amount:          amount,
		Currency:        currency,
		Status:          "created", // Initial status
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}

// CreatePaymentTransaction inserts a new payment transaction record into the database.
func CreatePaymentTransaction(ctx context.Context, db *pgxpool.Pool, tx *PaymentTransaction) (*PaymentTransaction, error) {
	logger.InfoLogger.Infof("Attempting to create payment transaction for booking ID: %s", tx.BookingID)

	if tx.ID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("failed to generate UUID: %w", err)
		}
		tx.ID = id
	}
	now := time.Now()
	tx.CreatedAt = now
	tx.UpdatedAt = now

	query := `
		INSERT INTO payment_transactions (
			id, booking_id, razorpay_order_id, razorpay_payment_id,
			amount, currency, status, captured_at, created_at, updated_at,
			payment_method, error_description
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		) RETURNING id`

	var insertedID uuid.UUID
	err := db.QueryRow(ctx, query,
		tx.ID, tx.BookingID, tx.RazorpayOrderID, tx.RazorpayPaymentID,
		tx.Amount, tx.Currency, tx.Status, tx.CapturedAt, tx.CreatedAt, tx.UpdatedAt,
		tx.PaymentMethod, tx.ErrorDescription,
	).Scan(&insertedID)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to insert payment transaction into database for booking %s: %v", tx.BookingID, err)
		return nil, fmt.Errorf("failed to create payment transaction: %w", err)
	}

	tx.ID = insertedID
	logger.InfoLogger.Infof("Payment transaction with ID %s created successfully for booking %s", tx.ID, tx.BookingID)
	return tx, nil
}

// UpdatePaymentTransaction updates an existing payment transaction record.
func UpdatePaymentTransaction(ctx context.Context, db *pgxpool.Pool, tx *PaymentTransaction) error {
	logger.InfoLogger.Infof("Attempting to update payment transaction ID: %s, Status: %s", tx.ID, tx.Status)

	tx.UpdatedAt = time.Now()

	query := `
		UPDATE payment_transactions
		SET
			razorpay_payment_id = $2,
			amount = $3,
			currency = $4,
			status = $5,
			captured_at = $6,
			updated_at = $7,
			payment_method = $8,
			error_description = $9
		WHERE id = $1`

	cmdTag, err := db.Exec(ctx, query,
		tx.ID, tx.RazorpayPaymentID, tx.Amount, tx.Currency, tx.Status,
		tx.CapturedAt, tx.UpdatedAt, tx.PaymentMethod, tx.ErrorDescription,
	)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update payment transaction %s: %v", tx.ID, err)
		return fmt.Errorf("failed to update payment transaction: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("payment transaction with ID %s not found for update", tx.ID)
	}

	logger.InfoLogger.Infof("Payment transaction ID %s updated successfully to status %s", tx.ID, tx.Status)
	return nil
}

// GetPaymentTransactionByRazorpayOrderID fetches a payment transaction record by its Razorpay Order ID.
func GetPaymentTransactionByRazorpayOrderID(ctx context.Context, db *pgxpool.Pool, razorpayOrderID string) (*PaymentTransaction, error) {
	logger.InfoLogger.Infof("Attempting to fetch payment transaction by Razorpay Order ID: %s", razorpayOrderID)

	tx := &PaymentTransaction{}
	query := `
		SELECT id, booking_id, razorpay_order_id, razorpay_payment_id, amount, currency, status, captured_at, created_at, updated_at, payment_method, error_description
		FROM payment_transactions
		WHERE razorpay_order_id = $1`

	err := db.QueryRow(ctx, query, razorpayOrderID).Scan(
		&tx.ID, &tx.BookingID, &tx.RazorpayOrderID, &tx.RazorpayPaymentID,
		&tx.Amount, &tx.Currency, &tx.Status, &tx.CapturedAt, &tx.CreatedAt, &tx.UpdatedAt,
		&tx.PaymentMethod, &tx.ErrorDescription,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.WarnLogger.Warnf("Payment transaction with Razorpay Order ID %s not found", razorpayOrderID)
			return nil, fmt.Errorf("payment transaction not found")
		}
		logger.ErrorLogger.Errorf("Failed to fetch payment transaction by Razorpay Order ID %s: %v", razorpayOrderID, err)
		return nil, fmt.Errorf("database error fetching payment transaction: %w", err)
	}
	logger.InfoLogger.Infof("Payment transaction with Razorpay Order ID %s fetched successfully", razorpayOrderID)
	return tx, nil
}
