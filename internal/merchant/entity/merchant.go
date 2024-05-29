package entity

import (
	"database/sql"
	"errors"
	"net/url"
	"time"
)

type MerchantItem struct {
	ID              int          `db:"id_merchant_item" json:"itemId"`
	Name            string       `db:"name" json:"name"`
	ProductCategory string       `db:"product_category" json:"productCategory"`
	Price           float64      `db:"price" json:"price"`
	ImageURL        string       `db:"image_url" json:"imageUrl"`
	CreatedAt       time.Time    `db:"created_at" json:"created_at"`
	UpdatedAt       sql.NullTime `db:"updated_at" json:"updated_at"`
}

type CreateMerchantItemRequest struct {
	Name            string  `json:"name" validate:"required,min=2,max=30"`
	ProductCategory string  `json:"productCategory" validate:"required,oneof=Beverage Food Snack Condiments Additions"`
	Price           float64 `json:"price" validate:"required,min=1"`
	ImageURL        string  `json:"imageUrl" validate:"required,url"`
}

type CreateMerchantItemResponse struct {
	ItemID string `json:"itemId"`
}

type GetMerchantItemsResponse struct {
	Data []MerchantItem `json:"data"`
	Meta MetaData       `json:"meta"`
}

type MetaData struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
	Total  int `json:"total"`
}

func (req *CreateMerchantItemRequest) Validate() error {
	if len(req.Name) < 2 || len(req.Name) > 30 {
		return errors.New("name must be between 2 and 30 characters long")
	}
	validCategories := map[string]bool{
		"Beverage":   true,
		"Food":       true,
		"Snack":      true,
		"Condiments": true,
		"Additions":  true,
	}
	if !validCategories[req.ProductCategory] {
		return errors.New("invalid product category")
	}
	if req.Price < 1 {
		return errors.New("price must be at least 1")
	}
	_, err := url.ParseRequestURI(req.ImageURL)
	if err != nil {
		return errors.New("imageUrl must be a valid URL")
	}
	return nil
}
