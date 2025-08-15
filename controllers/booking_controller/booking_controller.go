package booking_controller

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joy095/identity/controllers/slot_booking_controller"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/booking_models"
	"github.com/joy095/identity/models/schedule_slot_models"
	"github.com/joy095/identity/models/shared_models"
	"github.com/joy095/identity/utils"
)

// BookingController handles all booking-related HTTP requests
type BookingController struct {
	Service *slot_booking_controller.SlotBookingService
}

// BookingResponse represents the standardized booking response
type BookingResponse struct {
	Booking          *booking_models.Booking `json:"booking"`
	PaymentSessionID string                  `json:"payment_session_id,omitempty"`
	Message          string                  `json:"message"`
}

// BookingListResponse represents paginated booking list response
type BookingListResponse struct {
	Bookings   []booking_models.Booking `json:"bookings"`
	TotalCount int                      `json:"total_count"`
	Page       int                      `json:"page"`
	Limit      int                      `json:"limit"`
	HasMore    bool                     `json:"has_more"`
}

// BookingAnalytics represents booking statistics
type BookingAnalytics struct {
	TotalBookings     int                   `json:"total_bookings"`
	ConfirmedBookings int                   `json:"confirmed_bookings"`
	PendingBookings   int                   `json:"pending_bookings"`
	CancelledBookings int                   `json:"cancelled_bookings"`
	FailedBookings    int                   `json:"failed_bookings"`
	TotalRevenue      float64               `json:"total_revenue"`
	StatusBreakdown   map[string]int        `json:"status_breakdown"`
	MonthlyStats      []MonthlyBookingStats `json:"monthly_stats"`
}

// MonthlyBookingStats represents monthly booking statistics
type MonthlyBookingStats struct {
	Month        string  `json:"month"`
	BookingCount int     `json:"booking_count"`
	Revenue      float64 `json:"revenue"`
}

// ReserveSlot handles slot reservation requests
func (bc *BookingController) ReserveSlot(c *gin.Context) {
	var req slot_booking_controller.SlotBookingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.WarnLogger.Warnf("Invalid reserve slot request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}

	// Get customer ID from JWT token
	customerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	req.CustomerID = customerID

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := bc.Service.CheckAndReserveSlot(ctx, &req); err != nil {
		logger.ErrorLogger.Errorf("Failed to reserve slot %s for customer %s: %v", req.SlotID, req.CustomerID, err)
		c.JSON(http.StatusConflict, gin.H{"error": "Failed to reserve slot", "details": err.Error()})
		return
	}

	logger.InfoLogger.Infof("Slot %s successfully reserved for customer %s", req.SlotID, req.CustomerID)
	c.JSON(http.StatusOK, gin.H{
		"message":    "Slot reserved successfully",
		"slot_id":    req.SlotID,
		"expires_at": time.Now().Add(slot_booking_controller.RedisSlotExpiry),
	})
}

// BookSlot handles complete slot booking with payment
func (bc *BookingController) BookSlot(c *gin.Context) {
	var req slot_booking_controller.SlotBookingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.WarnLogger.Warnf("Invalid book slot request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}

	// Get customer ID from JWT token
	customerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	req.CustomerID = customerID

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	booking, paymentSessionID, err := bc.Service.BookSlot(ctx, &req)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to book slot %s for customer %s: %v", req.SlotID, req.CustomerID, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to book slot", "details": err.Error()})
		return
	}

	logger.InfoLogger.Infof("Slot %s successfully booked for customer %s, booking ID: %s", req.SlotID, req.CustomerID, booking.ID)
	c.JSON(http.StatusCreated, BookingResponse{
		Booking:          booking,
		PaymentSessionID: paymentSessionID,
		Message:          "Booking created successfully. Complete payment to confirm.",
	})
}

// CancelSlotReservation releases a reserved slot
func (bc *BookingController) CancelSlotReservation(c *gin.Context) {
	slotIDStr := c.Param("slot_id")
	slotID, err := uuid.Parse(slotIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid slot ID format"})
		return
	}

	customerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bc.Service.ReleaseSlotReservation(ctx, slotID, customerID)

	logger.InfoLogger.Infof("Slot reservation %s cancelled by customer %s", slotID, customerID)
	c.JSON(http.StatusOK, gin.H{"message": "Slot reservation cancelled successfully"})
}

// GetMyBookings retrieves bookings for the authenticated user
func (bc *BookingController) GetMyBookings(c *gin.Context) {
	customerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}
	limit, err := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if err != nil || limit < 1 || limit > 100 {
		limit = 10 // Default and max limit validation
	}
	status := c.Query("status")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bookings, totalCount, err := bc.getBookingsByCustomer(ctx, customerID, status, page, limit)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch bookings for customer %s: %v", customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch bookings"})
		return
	}

	c.JSON(http.StatusOK, BookingListResponse{
		Bookings:   bookings,
		TotalCount: totalCount,
		Page:       page,
		Limit:      limit,
		HasMore:    page*limit < totalCount,
	})
}

// GetBookingDetails retrieves detailed information about a specific booking
func (bc *BookingController) GetBookingDetails(c *gin.Context) {
	bookingIDStr := c.Param("booking_id")
	bookingID, err := uuid.Parse(bookingIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid booking ID format"})
		return
	}

	customerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	booking, err := booking_models.GetBookingByID(ctx, bc.Service.DB, bookingID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch booking %s: %v", bookingID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Booking not found"})
		return
	}

	// Ensure customer can only access their own bookings
	if booking.CustomerID != customerID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"booking": booking})
}

// CancelBooking cancels a booking
func (bc *BookingController) CancelBooking(c *gin.Context) {
	bookingIDStr := c.Param("booking_id")
	bookingID, err := uuid.Parse(bookingIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid booking ID format"})
		return
	}

	customerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	booking, err := booking_models.GetBookingByID(ctx, bc.Service.DB, bookingID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Booking not found"})
		return
	}

	if booking.CustomerID != customerID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if booking.Status == string(shared_models.BookingStatusCancelled) {
		c.JSON(http.StatusConflict, gin.H{"error": "Booking is already cancelled"})
		return
	}

	if booking.Status == string(shared_models.BookingStatusConfirmed) {
		// You might want to implement refund logic here
		logger.WarnLogger.Warnf("Customer %s cancelling confirmed booking %s", customerID, bookingID)
	}

	err = booking_models.UpdateBookingStatus(ctx, bc.Service.DB, bookingID, shared_models.BookingStatusCancelled)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to cancel booking %s: %v", bookingID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel booking"})
		return
	}

	// Release slot availability if it was confirmed
	if booking.Status == string(shared_models.BookingStatusConfirmed) {
		schedule_slot_models.UpdateScheduleSlotAvailability(ctx, bc.Service.DB, booking.SlotID, true)
	}

	logger.InfoLogger.Infof("Booking %s cancelled by customer %s", bookingID, customerID)
	c.JSON(http.StatusOK, gin.H{"message": "Booking cancelled successfully"})
}

// GetBookingHistory retrieves booking history with filters
func (bc *BookingController) GetBookingHistory(c *gin.Context) {
	customerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Parse query parameters for filtering
	fromDate := c.Query("from_date")
	toDate := c.Query("to_date")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bookings, totalCount, err := bc.getBookingHistory(ctx, customerID, fromDate, toDate, page, limit)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch booking history for customer %s: %v", customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch booking history"})
		return
	}

	c.JSON(http.StatusOK, BookingListResponse{
		Bookings:   bookings,
		TotalCount: totalCount,
		Page:       page,
		Limit:      limit,
		HasMore:    page*limit < totalCount,
	})
}

// GetBookingsByStatus retrieves bookings by status
func (bc *BookingController) GetBookingsByStatus(c *gin.Context) {
	status := c.Param("status")
	customerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bookings, totalCount, err := bc.getBookingsByCustomer(ctx, customerID, status, page, limit)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch bookings by status %s for customer %s: %v", status, customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch bookings"})
		return
	}

	c.JSON(http.StatusOK, BookingListResponse{
		Bookings:   bookings,
		TotalCount: totalCount,
		Page:       page,
		Limit:      limit,
		HasMore:    page*limit < totalCount,
	})
}

// HandleCashfreeWebhook processes Cashfree payment webhooks
func (bc *BookingController) HandleCashfreeWebhook(c *gin.Context) {
	signature := c.GetHeader("x-webhook-signature")
	if signature == "" {
		logger.WarnLogger.Warn("Cashfree webhook received without signature")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing webhook signature"})
		return
	}

	body, err := c.GetRawData()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to read webhook body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	err = bc.Service.HandleCashfreeWebhook(ctx, signature, string(body))
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to process Cashfree webhook: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to process webhook"})
		return
	}

	logger.InfoLogger.Info("Cashfree webhook processed successfully")
	c.JSON(http.StatusOK, gin.H{"message": "Webhook processed successfully"})
}

// Business Owner Methods

// GetBusinessBookings retrieves all bookings for a business
func (bc *BookingController) GetBusinessBookings(c *gin.Context) {
	businessIDStr := c.Param("business_id")
	businessID, err := uuid.Parse(businessIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID format"})
		return
	}

	// TODO: Add business owner authorization check here

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	status := c.Query("status")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bookings, totalCount, err := bc.getBookingsByBusiness(ctx, businessID, status, page, limit)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch bookings for business %s: %v", businessID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch bookings"})
		return
	}

	c.JSON(http.StatusOK, BookingListResponse{
		Bookings:   bookings,
		TotalCount: totalCount,
		Page:       page,
		Limit:      limit,
		HasMore:    page*limit < totalCount,
	})
}

// GetTodayBookings retrieves today's bookings for a business
func (bc *BookingController) GetTodayBookings(c *gin.Context) {
	businessIDStr := c.Param("business_id")
	businessID, err := uuid.Parse(businessIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID format"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	today := time.Now().Format("2006-01-02")
	bookings, err := bc.getTodayBookings(ctx, businessID, today)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch today's bookings for business %s: %v", businessID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch today's bookings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"bookings": bookings,
		"date":     today,
		"count":    len(bookings),
	})
}

// GetUpcomingBookings retrieves upcoming bookings for a business
func (bc *BookingController) GetUpcomingBookings(c *gin.Context) {
	businessIDStr := c.Param("business_id")
	businessID, err := uuid.Parse(businessIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID format"})
		return
	}

	days, _ := strconv.Atoi(c.DefaultQuery("days", "7")) // Default to next 7 days

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bookings, err := bc.getUpcomingBookings(ctx, businessID, days)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch upcoming bookings for business %s: %v", businessID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch upcoming bookings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"bookings": bookings,
		"days":     days,
		"count":    len(bookings),
	})
}

// UpdateBookingStatus updates the status of a booking (business owner action)
func (bc *BookingController) UpdateBookingStatus(c *gin.Context) {
	businessIDStr := c.Param("business_id")
	businessID, err := uuid.Parse(businessIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID format"})
		return
	}

	bookingIDStr := c.Param("booking_id")
	bookingID, err := uuid.Parse(bookingIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid booking ID format"})
		return
	}

	var req struct {
		Status string `json:"status" binding:"required"`
		Reason string `json:"reason,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate status values
	validStatuses := map[string]bool{
		string(shared_models.BookingStatusPending):   true,
		string(shared_models.BookingStatusConfirmed): true,
		string(shared_models.BookingStatusCancelled): true,
		string(shared_models.BookingStatusFailed):    true,
	}
	if !validStatuses[req.Status] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid status value"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Verify booking belongs to the business
	booking, err := booking_models.GetBookingByID(ctx, bc.Service.DB, bookingID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Booking not found"})
		return
	}

	if booking.BusinessID != businessID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Booking does not belong to this business"})
		return
	}

	err = booking_models.UpdateBookingStatus(ctx, bc.Service.DB, bookingID, req.Status)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update booking %s status: %v", bookingID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update booking status"})
		return
	}

	logger.InfoLogger.Infof("Booking %s status updated to %s by business %s", bookingID, req.Status, businessID)
	c.JSON(http.StatusOK, gin.H{
		"message": "Booking status updated successfully",
		"status":  req.Status,
	})
}

// Admin Methods

// GetAllBookings retrieves all bookings in the system (admin only)
func (bc *BookingController) GetAllBookings(c *gin.Context) {
	// TODO: Add admin authorization check here

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	status := c.Query("status")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bookings, totalCount, err := bc.getAllBookings(ctx, status, page, limit)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch all bookings: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch bookings"})
		return
	}

	c.JSON(http.StatusOK, BookingListResponse{
		Bookings:   bookings,
		TotalCount: totalCount,
		Page:       page,
		Limit:      limit,
		HasMore:    page*limit < totalCount,
	})
}

// GetBookingAnalytics retrieves booking analytics (admin only)
func (bc *BookingController) GetBookingAnalytics(c *gin.Context) {
	// TODO: Add admin authorization check here

	fromDate := c.Query("from_date")
	toDate := c.Query("to_date")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	analytics, err := bc.getBookingAnalytics(ctx, fromDate, toDate)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch booking analytics: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch analytics"})
		return
	}

	c.JSON(http.StatusOK, analytics)
}

// ForceCancelBooking force cancels a booking (admin only)
func (bc *BookingController) ForceCancelBooking(c *gin.Context) {
	// TODO: Add admin authorization check here

	bookingIDStr := c.Param("booking_id")
	bookingID, err := uuid.Parse(bookingIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid booking ID format"})
		return
	}

	var req struct {
		Reason string `json:"reason" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cancellation reason is required"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = booking_models.UpdateBookingStatus(ctx, bc.Service.DB, bookingID, shared_models.BookingStatusCancelled)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to force cancel booking %s: %v", bookingID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel booking"})
		return
	}

	logger.WarnLogger.Warnf("Booking %s force cancelled by admin. Reason: %s", bookingID, req.Reason)
	c.JSON(http.StatusOK, gin.H{
		"message": "Booking force cancelled successfully",
		"reason":  req.Reason,
	})
}

// Helper methods for database operations
// These would typically be moved to a service layer or repository pattern

func (bc *BookingController) getBookingsByCustomer(ctx context.Context, customerID uuid.UUID, status string, page, limit int) ([]booking_models.Booking, int, error) {
	return booking_models.GetBookingsByCustomer(ctx, bc.Service.DB, customerID, status, page, limit)
}

func (bc *BookingController) getBookingHistory(ctx context.Context, customerID uuid.UUID, fromDate, toDate string, page, limit int) ([]booking_models.Booking, int, error) {
	// For now, use the same function as getBookingsByCustomer with date filtering
	// You could enhance this to include date range filtering in the future
	return booking_models.GetBookingsByCustomer(ctx, bc.Service.DB, customerID, "", page, limit)
}

func (bc *BookingController) getBookingsByBusiness(ctx context.Context, businessID uuid.UUID, status string, page, limit int) ([]booking_models.Booking, int, error) {
	return booking_models.GetBookingsByBusiness(ctx, bc.Service.DB, businessID, status, page, limit)
}

func (bc *BookingController) getTodayBookings(ctx context.Context, businessID uuid.UUID, date string) ([]booking_models.Booking, error) {
	// Get today's bookings for the business
	// For now, get all bookings and filter in memory - this could be optimized with a proper date query
	bookings, _, err := booking_models.GetBookingsByBusiness(ctx, bc.Service.DB, businessID, "", 1, 1000)
	if err != nil {
		return nil, err
	}

	var todayBookings []booking_models.Booking
	for _, booking := range bookings {
		if booking.CreatedAt.Format("2006-01-02") == date {
			todayBookings = append(todayBookings, booking)
		}
	}

	return todayBookings, nil
}

func (bc *BookingController) getUpcomingBookings(ctx context.Context, businessID uuid.UUID, days int) ([]booking_models.Booking, error) {
	// Get upcoming bookings within the specified number of days
	bookings, _, err := booking_models.GetBookingsByBusiness(ctx, bc.Service.DB, businessID, "", 1, 1000)
	if err != nil {
		return nil, err
	}

	// Filter for upcoming bookings within the specified days
	now := time.Now()
	cutoffDate := now.AddDate(0, 0, days)

	var upcomingBookings []booking_models.Booking
	for _, booking := range bookings {
		if booking.CreatedAt.After(now) && booking.CreatedAt.Before(cutoffDate) {
			upcomingBookings = append(upcomingBookings, booking)
		}
	}

	return upcomingBookings, nil
}

func (bc *BookingController) getAllBookings(ctx context.Context, status string, page, limit int) ([]booking_models.Booking, int, error) {
	return booking_models.GetAllBookings(ctx, bc.Service.DB, status, page, limit)
}

func (bc *BookingController) getBookingAnalytics(ctx context.Context, fromDate, toDate string) (*BookingAnalytics, error) {
	// Get all bookings to calculate analytics
	bookings, totalCount, err := booking_models.GetAllBookings(ctx, bc.Service.DB, "", 1, 10000) // Get a large number to analyze
	if err != nil {
		return nil, err
	}

	analytics := &BookingAnalytics{
		TotalBookings:   totalCount,
		StatusBreakdown: make(map[string]int),
		MonthlyStats:    make([]MonthlyBookingStats, 0),
	}

	// Calculate status breakdown and other metrics
	for _, booking := range bookings {
		analytics.StatusBreakdown[booking.Status]++

		switch booking.Status {
		case "confirmed":
			analytics.ConfirmedBookings++
		case "pending":
			analytics.PendingBookings++
		case "cancelled":
			analytics.CancelledBookings++
		case "failed":
			analytics.FailedBookings++
		}
	}

	// TODO: Calculate revenue and monthly stats by joining with service pricing
	// This would require joining with services table to get pricing information

	return analytics, nil
}
