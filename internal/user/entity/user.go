package entity

import (
	"database/sql"
	"time"
)

type User struct {
	IdUser    uint32       `db:"id_user" json:"-"`
	Username  string       `db:"username" json:"username"`
	Email     string       `db:"email" json:"email"`
	Role      string       `db:"role" json:"-"`
	Password  string       `db:"password" json:"-"`
	Salt      string       `db:"salt" json:"-"`
	CreatedAt time.Time    `db:"created_at" json:"created_at"`
	UpdatedAt sql.NullTime `db:"updated_at" json:"updated_at"`
}

type UserRegisterParam struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"-"`
	Password string `json:"password"`
	Salt     string `json:"-"`
}

type UserLoginParam struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserResponse struct {
	Token string `json:"token"`
}
