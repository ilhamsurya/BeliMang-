package service

import (
	"context"
	"projectsphere/beli-mang/internal/merchant/entity"
	"projectsphere/beli-mang/internal/merchant/repository"
	"strconv"
	"time"

	"go.uber.org/zap"
)

type MerchantService struct {
	merchantRepository repository.MerchantRepositoryContract
	contextTimeout     time.Duration
}

func NewMerchantService(timeout time.Duration, merchantRepository repository.MerchantRepositoryContract) *MerchantService {
	return &MerchantService{
		merchantRepository: merchantRepository,
		contextTimeout:     timeout,
	}
}

func (s MerchantService) CreateMerchantItem(ctx context.Context, merchant entity.CreateMerchantItemRequest) (entity.CreateMerchantItemResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, s.contextTimeout)
	defer cancel()

	callerInfo := "[MerchantService.CreateMerchant]"
	l := zap.L().With(zap.String("caller", callerInfo))

	item, err := s.merchantRepository.CreateMerchantItem(ctx, merchant)
	if err != nil {
		l.Error("failed to create merchant item", zap.Error(err))
		return entity.CreateMerchantItemResponse{}, err
	}

	response := entity.CreateMerchantItemResponse{
		ItemID: strconv.Itoa(item.ID), // Convert ID from int to string
	}

	return response, nil
}
