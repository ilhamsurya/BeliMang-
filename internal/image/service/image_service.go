package service

import (
	"context"
	"errors"
	"mime/multipart"
	"path/filepath"
	"projectsphere/beli-mang/config"
	"projectsphere/beli-mang/internal/image/repository"
	"projectsphere/beli-mang/pkg/middleware/logger/zap/logger"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

type ImageService struct {
	imageRepository repository.ImageRepositoryContract
	contextTimeout  time.Duration
}

func NewImageService(timeout time.Duration, imageRepository repository.ImageRepositoryContract) *ImageService {
	return &ImageService{
		imageRepository: imageRepository,
		contextTimeout:  timeout,
	}
}

func (s ImageService) UploadImage(ctx context.Context, image *multipart.FileHeader) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.contextTimeout)
	defer cancel()

	callerInfo := "[ImageService.UploadImage]"
	l := logger.FromCtx(ctx).With(zap.String("caller", callerInfo))

	getExt := strings.Split(image.Filename, ".")
	if len(getExt) == 0 {
		l.Error("invalid image extension", zap.String("filename", image.Filename))
		return "", errors.New("failed to get image extension")
	}
	ext := getExt[len(getExt)-1]
	name := config.GetString("APP_NAME")
	timestamp := time.Now().Unix()

	image.Filename = filepath.Join(name + "_" + strconv.FormatInt(timestamp, 10) + "." + ext)

	url, err := s.imageRepository.UploadImage(ctx, image)
	if err != nil {
		l.Error("failed to upload image", zap.Error(err))
		return "", err
	}

	return url, nil
}

var _ ImageServiceContract = (*ImageService)(nil)
