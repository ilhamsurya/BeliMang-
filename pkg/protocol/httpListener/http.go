package httpListener

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"projectsphere/beli-mang/config"
	"projectsphere/beli-mang/pkg/database"
	"projectsphere/beli-mang/pkg/middleware/auth"
	"strconv"

	adapter "projectsphere/beli-mang/pkg/middleware/s3"

	merchantHandler "projectsphere/beli-mang/internal/merchant/handler"
	merchantRepository "projectsphere/beli-mang/internal/merchant/repository"
	merchantService "projectsphere/beli-mang/internal/merchant/service"

	imageHandler "projectsphere/beli-mang/internal/image/handler"
	imageRepository "projectsphere/beli-mang/internal/image/repository"
	imageService "projectsphere/beli-mang/internal/image/service"

	userHandler "projectsphere/beli-mang/internal/user/handler"
	userRepo "projectsphere/beli-mang/internal/user/repository"
	userService "projectsphere/beli-mang/internal/user/service"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap"
)

type HttpImpl struct {
	HttpRouter *HttpRouterImpl
	httpServer *http.Server
}

func NewHttpProtocol(
	HttpRouter *HttpRouterImpl,
) *HttpImpl {
	return &HttpImpl{
		HttpRouter: HttpRouter,
	}
}

func (p *HttpImpl) setupRouter() *gin.Engine {
	return p.HttpRouter.Router()
}

func (p *HttpImpl) Listen() {
	app := p.setupRouter()

	serverPort := fmt.Sprintf(":%v", config.GetString("APP_PORT"))
	p.httpServer = &http.Server{
		Addr:    serverPort,
		Handler: app,
	}

	log.Info().Msgf("Server started on Port %s ", serverPort)
	err := p.httpServer.ListenAndServe()
	if err != nil {
		log.Printf(err.Error())
	}
}

func (p *HttpImpl) Shutdown(ctx context.Context) error {
	if err := p.httpServer.Shutdown(ctx); err != nil {
		return err
	}
	return nil
}

func Start() *HttpImpl {
	callerInfo := "[server.Run]"
	l := zap.L().With(zap.String("caller", callerInfo))

	db, err := sqlx.Connect(
		"postgres",
		fmt.Sprintf("postgresql://%s:%s@%s:%v/%s?%s",
			config.GetString("DB_USERNAME"),
			config.GetString("DB_PASSWORD"),
			config.GetString("DB_HOST"),
			config.GetString("DB_PORT"),
			config.GetString("DB_NAME"),
			config.GetString("DB_PARAMS"),
		),
	)
	if err != nil {
		panic(err.Error())
	}

	postgresConnector := database.NewPostgresConnector(context.TODO(), db)

	accessTokenExpiredTime := 480
	jwtSecretKey := config.GetString("JWT_SECRET")
	strSaltLen := config.GetString("BCRYPT_SALT")

	saltLen, err := strconv.Atoi(strSaltLen)
	if err != nil {
		panic("cannot parse BCRYPT_SALT")
	}

	l.Debug("Server Config", zap.Any("ENV", os.Getenv("APP_ENV")))

	l.Info("Server is starting...")

	s3 := adapter.GetS3Client()

	userRepo := userRepo.NewUserRepo(postgresConnector)

	jwtAuth := auth.NewJwtAuth(
		accessTokenExpiredTime,
		jwtSecretKey,
		userRepo.IsUserExist,
	)

	userSvc := userService.NewUserService(userRepo, saltLen, jwtAuth)
	userHandler := userHandler.NewUserHandler(userSvc)

	imageRepo := imageRepository.NewImageRepository(s3)
	imageSvc := imageService.NewImageService(300, imageRepo)
	imageHandler := imageHandler.NewImageHandler(imageSvc)

	merchantRepo := merchantRepository.NewMerchantItemRepo(postgresConnector)
	merchantSvc := merchantService.NewMerchantService(300, merchantRepo)
	merchantHandler := merchantHandler.NewMerchantHandler(merchantSvc)

	httpHandlerImpl := NewHttpHandler(
		imageHandler,
		userHandler,
		merchantHandler,
		jwtAuth,
	)
	httpRouterImpl := NewHttpRoute(httpHandlerImpl)
	httpImpl := NewHttpProtocol(httpRouterImpl)

	return httpImpl
}
