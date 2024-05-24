package repository

import (
	"context"
	"mime/multipart"
	"projectsphere/beli-mang/config"
	"projectsphere/beli-mang/pkg/middleware/logger/zap/logger"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"go.uber.org/zap"
)

type ImageRepository struct {
	client   *s3.Client
	uploader *manager.Uploader
}

func NewImageRepository(client *s3.Client) *ImageRepository {
	return &ImageRepository{
		client:   client,
		uploader: manager.NewUploader(client),
	}
}

func (r ImageRepository) UploadImage(ctx context.Context, image *multipart.FileHeader) (string, error) {
	callerInfo := "[ImageRepository.UploadImage]"
	l := logger.FromCtx(ctx).With(zap.String("caller", callerInfo))

	img, err := image.Open()
	if err != nil {
		l.Error("error opening image", zap.Error(err))
		return "", err
	}

	params := &s3.PutObjectInput{
		Bucket: aws.String(config.GetString("BucketName")),
		Key:    aws.String(image.Filename),
		Body:   img,
	}

	result, err := r.uploader.Upload(ctx, params)
	if err != nil {
		l.Error("error uploading image", zap.Error(err))
		return "", err
	}

	return result.Location, nil
}

var _ ImageRepositoryContract = (*ImageRepository)(nil)
