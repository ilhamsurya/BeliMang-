package repository

import (
	"context"
	"projectsphere/beli-mang/internal/merchant/entity"
	"projectsphere/beli-mang/pkg/database"
	"projectsphere/beli-mang/pkg/protocol/msg"
	"time"
)

type MerchantItemRepo struct {
	dbConnector database.PostgresConnector
}

func NewMerchantItemRepo(dbConnector database.PostgresConnector) MerchantItemRepo {
	return MerchantItemRepo{
		dbConnector: dbConnector,
	}
}

func (r MerchantItemRepo) CreateMerchantItem(ctx context.Context, param entity.CreateMerchantItemRequest) (entity.MerchantItem, error) {
	query := `
  INSERT INTO merchant_items (name, product_category, price, image_url, created_at) 
  VALUES ($1, $2, $3, $4, $5) 
  RETURNING id_merchant_item, name, product_category, price, image_url, created_at, updated_at
  `

	var returnedRow entity.MerchantItem
	err := r.dbConnector.DB.GetContext(
		ctx,
		&returnedRow,
		query,
		param.Name,
		param.ProductCategory,
		param.Price,
		param.ImageURL,
		time.Now(),
	)
	if err != nil {
		return entity.MerchantItem{}, msg.InternalServerError(err.Error())
	}

	return returnedRow, nil
}
