package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/business_image_controller"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterBusinessImageRoutes(router *gin.Engine) {
	businessImageController := business_image_controller.NewBusinessImageController(db.DB)

	protected := router.Group("/")
	protected.Use(auth.AuthMiddleware())
	// All these routes operate on images belonging to a specific business (:publicId).
	businessImages := protected.Group("/business-image/:publicId")
	{
		// Add one or more new images to a business.
		businessImages.POST("", businessImageController.AddBusinessImages)
		// Replace an existing image.
		businessImages.PUT("/:imageId", businessImageController.ReplaceBusinessImage)
		// Delete a specific image from a business.
		businessImages.DELETE("/:imageId", businessImageController.DeleteBusinessImage)
		// Set a specific image as the primary one for the business.
		businessImages.PATCH("/:imageId/primary", businessImageController.SetPrimaryBusinessImage)
	}
}
