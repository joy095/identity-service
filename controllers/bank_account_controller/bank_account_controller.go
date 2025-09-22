package bank_account_controller

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/utils"
)

type BankAccount struct {
	BankID        string    `json:"bank_id"`
	UserID        uuid.UUID `json:"user_id"`
	AccountNumber string    `json:"account_number"`
	IFSC          string    `json:"ifsc"`
	BankName      string    `json:"bank_name"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type BankAccountController struct {
	DB *pgxpool.Pool
}

func NewBankAccountController(db *pgxpool.Pool) (*BankAccountController, error) {
	return &BankAccountController{DB: db}, nil
}

// CreateBankAccount - POST /bank-accounts
func (ctrl *BankAccountController) CreateBankAccount(c *gin.Context) {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req struct {
		AccountNumber string `json:"account_number" binding:"required"`
		IFSC          string `json:"ifsc" binding:"required"`
		BankName      string `json:"bank_name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	bankID := uuid.NewString()

	_, err = ctrl.DB.Exec(context.Background(),
		`INSERT INTO bank_accounts (bank_id, user_id, account_number, ifsc, bank_name, created_at, updated_at) 
		 VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
		bankID, userID, req.AccountNumber, req.IFSC, req.BankName,
	)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to insert bank account: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save bank account"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"bank_id": bankID,
		"status":  "created",
	})
}

// ListBankAccounts - GET /bank-accounts
func (ctrl *BankAccountController) ListBankAccounts(c *gin.Context) {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	rows, err := ctrl.DB.Query(context.Background(),
		`SELECT bank_id, account_number, ifsc, bank_name, created_at, updated_at 
		 FROM bank_accounts WHERE user_id = $1`, userID,
	)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to fetch bank accounts: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch bank accounts"})
		return
	}
	defer rows.Close()

	var accounts []BankAccount
	for rows.Next() {
		var acc BankAccount
		if err := rows.Scan(&acc.BankID, &acc.AccountNumber, &acc.IFSC, &acc.BankName, &acc.CreatedAt, &acc.UpdatedAt); err == nil {
			acc.UserID = userID
			accounts = append(accounts, acc)
		}
	}

	c.JSON(http.StatusOK, accounts)
}

// GetBankAccount - GET /bank-accounts/:bank_id
func (ctrl *BankAccountController) GetBankAccount(c *gin.Context) {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	bankID := c.Param("bank_id")

	var acc BankAccount
	err = ctrl.DB.QueryRow(context.Background(),
		`SELECT bank_id, account_number, ifsc, bank_name, created_at, updated_at
		 FROM bank_accounts WHERE bank_id = $1 AND user_id = $2`,
		bankID, userID,
	).Scan(&acc.BankID, &acc.AccountNumber, &acc.IFSC, &acc.BankName, &acc.CreatedAt, &acc.UpdatedAt)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "bank account not found"})
		return
	}

	acc.UserID = userID
	c.JSON(http.StatusOK, acc)
}

// UpdateBankAccount - PUT /bank-accounts/:bank_id
func (ctrl *BankAccountController) UpdateBankAccount(c *gin.Context) {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	bankID := c.Param("bank_id")

	var req struct {
		AccountNumber string `json:"account_number"`
		IFSC          string `json:"ifsc"`
		BankName      string `json:"bank_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	_, err = ctrl.DB.Exec(context.Background(),
		`UPDATE bank_accounts 
		 SET account_number = COALESCE(NULLIF($1, ''), account_number),
		     ifsc = COALESCE(NULLIF($2, ''), ifsc),
		     bank_name = COALESCE(NULLIF($3, ''), bank_name),
		     updated_at = NOW()
		 WHERE bank_id = $4 AND user_id = $5`,
		req.AccountNumber, req.IFSC, req.BankName, bankID, userID,
	)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to update bank account: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update bank account"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// DeleteBankAccount - DELETE /bank-accounts/:bank_id
func (ctrl *BankAccountController) DeleteBankAccount(c *gin.Context) {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	bankID := c.Param("bank_id")

	_, err = ctrl.DB.Exec(context.Background(),
		`DELETE FROM bank_accounts WHERE bank_id = $1 AND user_id = $2`,
		bankID, userID,
	)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to delete bank account: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete bank account"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}
