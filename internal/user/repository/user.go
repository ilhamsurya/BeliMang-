package repository

import (
	"context"
	"database/sql"
	"projectsphere/beli-mang/internal/user/entity"
	"projectsphere/beli-mang/pkg/database"
	"projectsphere/beli-mang/pkg/protocol/msg"
)

type UserRepo struct {
	dbConnector database.PostgresConnector
}

func NewUserRepo(dbConnector database.PostgresConnector) UserRepo {
	return UserRepo{
		dbConnector: dbConnector,
	}
}

func (r UserRepo) CreateUser(ctx context.Context, param entity.UserRegisterParam) (entity.User, error) {
	query := `
  INSERT INTO users (username, email, role, password, salt) VALUES ($1, $2, $3, $4, $5) RETURNING id_user, username, email, role, password, salt, created_at, updated_at
  `

	var returnedRow entity.User
	err := r.dbConnector.DB.GetContext(
		ctx,
		&returnedRow,
		query,
		param.Username,
		param.Email,
		param.Role,
		param.Password,
		param.Salt,
	)
	if err != nil {
		return entity.User{}, msg.InternalServerError(err.Error())
	}

	return returnedRow, nil
}

func (r UserRepo) IsUsernameAlreadyUsed(ctx context.Context, username string) bool {
	query := `
    SELECT 1 FROM users WHERE username = $1
  `
	result := 0
	err := r.dbConnector.DB.GetContext(
		ctx,
		&result,
		query,
		username,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		}

		panic(err.Error())
	}

	return result == 1
}

// user email can't duplicate with admin email but can with another user email
func (r UserRepo) IsUserEmailConflictedAdminEmail(ctx context.Context, email string) bool {
	query := `
    SELECT 1 FROM users WHERE email = $1 AND role = 'admin'
  `
	result := 0
	err := r.dbConnector.DB.GetContext(
		ctx,
		&result,
		query,
		email,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		}
		panic(err.Error())
	}

	return result == 1
}

func (r UserRepo) IsUserExist(ctx context.Context, userId uint32) bool {
	query := `
		SELECT 1 FROM users WHERE id_user = $1
	`

	result := 0
	err := r.dbConnector.DB.GetContext(
		ctx,
		&result,
		query,
		userId,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		}

		panic(err.Error())
	}

	return result == 1
}
