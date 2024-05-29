package handler

import (
	"net/http"
	"net/url"
	"projectsphere/beli-mang/internal/merchant/entity"
	"projectsphere/beli-mang/internal/merchant/service"
	"projectsphere/beli-mang/pkg/protocol/msg"

	"github.com/gin-gonic/gin"
)

type MerchantHandler struct {
	merchantHandler service.MerchantRepositoryContract
}

func NewMerchantHandler(merchantHandler service.MerchantRepositoryContract) MerchantHandler {
	return MerchantHandler{
		merchantHandler: merchantHandler,
	}
}

func (h MerchantHandler) Create(c *gin.Context) {

	if c.GetHeader("Authorization") == "" {
		c.JSON(http.StatusUnauthorized, msg.Unauthorization("No authorization header provided"))
		return
	}

	if c.Request.Body == nil {
		c.JSON(http.StatusBadRequest, msg.BadRequest("Request body is empty"))
		return
	}
	payload := new(entity.CreateMerchantItemRequest)
	err := c.ShouldBindJSON(payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, msg.BadRequest(err.Error()))
		return
	}

	if containsNull(payload) {
		c.JSON(http.StatusBadRequest, msg.BadRequest("JSON payload contains null values"))
		return
	}

	resp, err := h.merchantHandler.CreateMerchantItem(c.Request.Context(), *payload)
	if err != nil {
		respError := msg.UnwrapRespError(err)
		c.JSON(respError.Code, respError)
		return
	}

	c.JSON(http.StatusCreated, resp)
}

func containsNull(param *entity.CreateMerchantItemRequest) bool {
	if param == nil {
		return true
	}
	if param.Name == "" || len(param.Name) < 2 || len(param.Name) > 30 {
		return true
	}
	validCategories := map[string]bool{
		"Beverage":   true,
		"Food":       true,
		"Snack":      true,
		"Condiments": true,
		"Additions":  true,
	}
	if _, valid := validCategories[param.ProductCategory]; !valid {
		return true
	}
	if param.Price < 1 {
		return true
	}

	if param.ImageURL == "" || !isValidURL(param.ImageURL) {
		return true
	}

	return false
}

// Helper function to validate URL
func isValidURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}
