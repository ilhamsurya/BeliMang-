package httpListener

import (
	"net/http"
	"projectsphere/beli-mang/config"
	"projectsphere/beli-mang/pkg/middleware/auth"
	"projectsphere/beli-mang/pkg/middleware/logger"
	"projectsphere/beli-mang/pkg/protocol/msg"

	imageHandler "projectsphere/beli-mang/internal/image/handler"
	userHandler "projectsphere/beli-mang/internal/user/handler"

	"github.com/gin-gonic/gin"
)

type HttpHandlerImpl struct {
	imageHandler imageHandler.ImageHandler
	userHandler  userHandler.UserHandler
	jwtAuth      auth.JWTAuth
}

func NewHttpHandler(
	imageHandler imageHandler.ImageHandler,
	ususerHandler userHandler.UserHandler,
	jwtAuth auth.JWTAuth,
) *HttpHandlerImpl {
	return &HttpHandlerImpl{
		imageHandler: imageHandler,
		userHandler:  ususerHandler,
		jwtAuth:      jwtAuth,
	}
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Disposition, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST,HEAD,PATCH, OPTIONS, GET, PUT, DELETE")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func (h *HttpHandlerImpl) Router() *gin.Engine {
	server := gin.New()
	server.Use(gin.Recovery(), logger.Logger(), CORSMiddleware())
	server.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, msg.NotFound(msg.ErrPageNotFound))
	})

	server.Static("/v1/docs", "./dist")

	r := server.Group(config.GetString("APPLICATION_GROUP"))

	image := r.Group("/image")
	image.Use(h.jwtAuth.JwtAuthUserMiddleware())
	image.POST("/", h.imageHandler.UploadImage)

	userGroup := r.Group("/users")
	userGroup.POST("/register", h.userHandler.RegisterUser)
	userGroup.POST("/login", h.userHandler.LoginUser)

	adminGroup := r.Group("/admin")
	adminGroup.POST("/register", h.userHandler.RegisterAdmin)
	adminGroup.POST("/login", h.userHandler.LoginAdmin)

	return server
}
