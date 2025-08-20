package booking_controller

import (
	"github.com/gin-gonic/gin"
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

func (bc *BookingController) Book(c *gin.Context) {

}
