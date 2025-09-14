package booking_controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/booking_models"
	"github.com/joy095/identity/utils"
)

// BookingController handles HTTP requests for schedule slots management
type BookingController struct {
	DB *pgxpool.Pool
}

// NewBookingController creates a new schedule slot controller
func NewBookingController(db *pgxpool.Pool) *BookingController {
	return &BookingController{
		DB: db,
	}
}

func (bc *BookingController) GetBookingByUser(c *gin.Context) {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		logger.ErrorLogger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	bookings, err := booking_models.GetBookingByUserModels(c.Request.Context(), bc.DB, userID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get booking: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve booking"})
		return
	}

	// Optional: check that all bookings belong to this user (redundant since WHERE o.customer_id = $1)
	for _, b := range bookings {
		if b.CustomerID != userID {
			logger.ErrorLogger.Error("Not authorized to view these orders")
			c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"bookings": bookings})
}

func (bc *BookingController) GetBookingId(c *gin.Context) {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		logger.ErrorLogger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	orderIDStr := c.Param("id")
	if orderIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Business orderId is required"})
		return
	}

	// Convert string to uuid.UUID
	orderID, err := uuid.Parse(orderIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid UUID format: %s", orderIDStr)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid orderId format"})
		return
	}

	order, err := booking_models.GetBookingByIdModels(c.Request.Context(), bc.DB, userID, orderID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get booking: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve booking"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"order": order})
}
