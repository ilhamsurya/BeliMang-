package handler

import (
	"sync"
)

var baseResponsePool = sync.Pool{
	New: func() any {
		return new(baseResponse)
	},
}

func baseResponseAcquire() *baseResponse {
	return baseResponsePool.Get().(*baseResponse)
}

func baseResponseRelease(t *baseResponse) {
	*t = baseResponse{}
	baseResponsePool.Put(t)
}

type baseResponse struct {
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

var imageUploadResPool = sync.Pool{
	New: func() any {
		return new(imageUploadRes)
	},
}

func imageUploadResAcquire() *imageUploadRes {
	return imageUploadResPool.Get().(*imageUploadRes)
}

func imageUploadResRelease(t *imageUploadRes) {
	*t = imageUploadRes{}
	imageUploadResPool.Put(t)
}

type imageUploadRes struct {
	ImgURL string `json:"imageUrl"`
}
