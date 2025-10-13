package routes

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/video_controller"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterVideoRoutes(router *gin.Engine) {
	vc, err := video_controller.NewVideoController(db.DB)
	if err != nil {
		panic(fmt.Errorf("failed to initialize video controller: %w", err))
	}

	protected := router.Group("/")
	protected.Use(auth.AuthMiddleware())
	{
		protected.GET("/room/:orderId", vc.JoinVideo)
	}
}
