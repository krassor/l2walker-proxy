package dto

import "time"

type RequestUserSignUpDto struct {
	FirstName  string `json:"firstName"`
	SecondName string `json:"secondName"`
	Phone      string `json:"phone"`
	Email      string `json:"email"`
	Password   string `json:"password"`
}

type ResponseUserSignUpDto struct {
	AccessToken string `json:"accessToken"`
}

type RequestUserSignInDto struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type ResponseUserSignInDto struct {
	AccessToken string `json:"accessToken"`
}

type UserDto struct {
    ID          string    `json:"id"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
    FirstName   string    `json:"first_name"`
    MiddleName  string    `json:"middle_name"`
    SecondName  string    `json:"second_name"`
    Email       string    `json:"email"`
    Phone       string    `json:"phone"`
    TelegramId  string    `json:"telegram_id"`
}