package handler

import (
	"net/http"
	"projectsphere/beli-mang/internal/user/entity"
	"projectsphere/beli-mang/internal/user/service"
	"projectsphere/beli-mang/pkg/protocol/msg"

	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	userSvc service.UserService
}

func NewUserHandler(userSvc service.UserService) UserHandler {
	return UserHandler{
		userSvc: userSvc,
	}
}

func (h UserHandler) RegisterUser(c *gin.Context) {
	payload := new(entity.UserRegisterParam)

	err := c.ShouldBindJSON(payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, msg.BadRequest(err.Error()))
		return
	}

	payload.Role = "user"

	resp, err := h.userSvc.Register(c.Request.Context(), payload)
	if err != nil {
		respError := msg.UnwrapRespError(err)
		c.JSON(respError.Code, respError)
		return
	}

	c.JSON(http.StatusCreated, msg.ReturnResult("User registered successfully", resp))
}

func (h UserHandler) RegisterAdmin(c *gin.Context) {
	payload := new(entity.UserRegisterParam)

	err := c.ShouldBindJSON(payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, msg.BadRequest(err.Error()))
		return
	}

	payload.Role = "admin"

	resp, err := h.userSvc.Register(c.Request.Context(), payload)
	if err != nil {
		respError := msg.UnwrapRespError(err)
		c.JSON(respError.Code, respError)
		return
	}

	c.JSON(http.StatusCreated, msg.ReturnResult("Admin registered successfully", resp))
}

func (h UserHandler) LoginUser(c *gin.Context) {
	payload := new(entity.UserLoginParam)

	err := c.ShouldBindJSON(payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, msg.BadRequest(err.Error()))
		return
	}

	resp, err := h.userSvc.Login(c.Request.Context(), *payload)
	if err != nil {
		respError := msg.UnwrapRespError(err)
		c.JSON(respError.Code, respError)
		return
	}

	c.JSON(http.StatusOK, msg.ReturnResult("User logged successfully", resp))
}

func (h UserHandler) LoginAdmin(c *gin.Context) {
	payload := new(entity.UserLoginParam)

	err := c.ShouldBindJSON(payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, msg.BadRequest(err.Error()))
		return
	}

	resp, err := h.userSvc.Login(c.Request.Context(), *payload)
	if err != nil {
		respError := msg.UnwrapRespError(err)
		c.JSON(respError.Code, respError)
		return
	}

	c.JSON(http.StatusOK, msg.ReturnResult("Admin logged successfully", resp))
}
