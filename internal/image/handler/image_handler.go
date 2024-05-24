package handler

import (
	"net/http"
	"projectsphere/beli-mang/internal/image/service"
	"projectsphere/beli-mang/pkg/middleware/logger/zap/logger"
	"projectsphere/beli-mang/pkg/protocol/msg"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type ImageHandler struct {
	imageService service.ImageServiceContract
}

func NewImageHandler(imageService service.ImageServiceContract) ImageHandler {
	return ImageHandler{
		imageService: imageService,
	}
}

func (h ImageHandler) UploadImage(c *gin.Context) {
	callerInfo := "[imageHandler.UploadImage]"

	userCtx := c.Request.Context()
	l := logger.FromCtx(userCtx).With(zap.String("caller", callerInfo))

	// Get file
	file, err := c.FormFile("file")
	if err != nil {
		l.Error("error parsing request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}

	// Validate File
	const minSize, maxSize = 10 * 1024, 2 * 1024 * 1024
	if file.Size < int64(minSize) || file.Size > int64(maxSize) {
		l.Error("invalid file size")
		c.JSON(http.StatusBadRequest, msg.BadRequest("file size must be between 10KB and 2MB"))
		return

	}

	if file.Header.Get("Content-Type") != "image/jpeg" {
		l.Error("invalid file type")
		c.JSON(http.StatusBadRequest, msg.BadRequest("file type must be image/jpeg"))
		return
	}

	url, err := h.imageService.UploadImage(userCtx, file)
	if err != nil {
		l.Error("error uploading image", zap.Error(err))
		c.JSON(http.StatusBadRequest, msg.BadRequest("error uploading image"))
		return
	}

	res := baseResponseAcquire()
	defer baseResponseRelease(res)

	res.Message = "File uploaded successfully"

	imgURL := imageUploadResAcquire()
	defer imageUploadResRelease(imgURL)

	imgURL.ImgURL = url

	res.Data = imgURL

	c.JSON(http.StatusOK, res)
}
