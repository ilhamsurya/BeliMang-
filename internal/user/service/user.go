package service

import (
	"context"
	"projectsphere/beli-mang/internal/user/entity"
	"projectsphere/beli-mang/internal/user/repository"
	"projectsphere/beli-mang/pkg/middleware/auth"
	"projectsphere/beli-mang/pkg/protocol/msg"
	"projectsphere/beli-mang/pkg/validator"
)

type UserService struct {
	userRepo repository.UserRepo
	saltLen  int
	jwtAuth  auth.JWTAuth
}

func NewUserService(userRepo repository.UserRepo, saltLen int, jwtAuth auth.JWTAuth) UserService {
	return UserService{
		userRepo: userRepo,
		saltLen:  saltLen,
		jwtAuth:  jwtAuth,
	}
}

func (u UserService) Register(ctx context.Context, param *entity.UserRegisterParam) (entity.UserResponse, error) {
	if !validator.IsValidUsername(param.Username) {
		return entity.UserResponse{}, msg.BadRequest(msg.ErrInvalidUsername)
	}

	if !validator.IsValidEmail(param.Email) {
		return entity.UserResponse{}, msg.BadRequest(msg.ErrInvalidEmail)
	}

	if !validator.IsSolidPassword(param.Password) {
		return entity.UserResponse{}, msg.BadRequest(msg.ErrInvalidPassword)
	}

	if u.userRepo.IsUsernameAlreadyUsed(ctx, param.Username) {
		return entity.UserResponse{}, &msg.RespError{
			Code:    409,
			Message: msg.ErrUsernameAlreadyExist,
		}
	}

	if u.userRepo.IsUserEmailConflictedAdminEmail(ctx, param.Email) {
		return entity.UserResponse{}, &msg.RespError{
			Code:    409,
			Message: msg.ErrEmailAlreadyExist,
		}
	}

	param.Salt = auth.GenerateRandomAlphaNumeric(int(u.saltLen))
	hashedPassword := auth.GenerateHash([]byte(param.Password), []byte(param.Salt))
	param.Password = hashedPassword

	user, err := u.userRepo.CreateUser(ctx, *param)
	if err != nil {
		return entity.UserResponse{}, err
	}

	accessToken, err := u.jwtAuth.GenerateToken(user.IdUser, user.Role)
	if err != nil {
		return entity.UserResponse{}, err
	}

	return entity.UserResponse{
		Token: accessToken,
	}, nil
}

func (u UserService) Login(ctx context.Context, param entity.UserLoginParam) (entity.UserResponse, error) {
	if !validator.IsValidUsername(param.Username) {
		return entity.UserResponse{}, msg.BadRequest(msg.ErrInvalidUsername)
	}

	if !validator.IsSolidPassword(param.Password) {
		return entity.UserResponse{}, msg.BadRequest(msg.ErrInvalidPassword)
	}

	user, err := u.userRepo.GetUserByUsername(ctx, param.Username)
	if err != nil {
		return entity.UserResponse{}, err
	}

	err = auth.CompareHash(user.Password, param.Password, user.Salt)
	if err != nil {
		return entity.UserResponse{}, msg.BadRequest(msg.ErrWrongPassword)
	}

	accessToken, err := u.jwtAuth.GenerateToken(user.IdUser, user.Role)
	if err != nil {
		return entity.UserResponse{}, err
	}

	return entity.UserResponse{
		Token: accessToken,
	}, nil
}
