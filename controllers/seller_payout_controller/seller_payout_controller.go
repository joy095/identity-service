package seller_payout_controller

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SellerPaymentController struct{ db *pgxpool.Pool }

// NewSellerPaymentController creates and returns a new instance of SellerPaymentController
func NewSellerPaymentController(db *pgxpool.Pool) (*SellerPaymentController, error) {
	if db == nil {
		return nil, errors.New("database pool cannot be nil")
	}

	return &SellerPaymentController{
		db: db,
	}, nil
}

func (sp *SellerPaymentController) SellerPayout(c *gin.Context) {
	
}
