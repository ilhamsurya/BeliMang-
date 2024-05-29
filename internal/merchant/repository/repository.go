package repository

import (
	"context"
	"projectsphere/beli-mang/internal/merchant/entity"
)

type MerchantRepositoryContract interface {
	CreateMerchantItem(ctx context.Context, item entity.CreateMerchantItemRequest) (entity.MerchantItem, error)
	// GetMerchantItems(ctx context.Context, filter *entity.MetaData, item entity.MerchantItem) (entity.MerchantItem, error)
}
