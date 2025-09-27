package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/bank_account_controller"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterBankAccountRoutes(r *gin.Engine) {
	bankAccountController, err := bank_account_controller.NewBankAccountController(db.DB)
	if err != nil {
		logger.ErrorLogger.Fatalf("failed to initialize bank account controller: %v", err)
	}

	api := r.Group("/bank-accounts")
	api.Use(auth.AuthMiddleware())
	{
		api.POST("/", bankAccountController.CreateBankAccount)
		api.GET("/", bankAccountController.ListBankAccounts)
		api.GET("/:bank_id", bankAccountController.GetBankAccount)
		api.PUT("/:bank_id", bankAccountController.UpdateBankAccount)
		api.DELETE("/:bank_id", bankAccountController.DeleteBankAccount)
	}
}
