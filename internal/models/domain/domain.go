package domain

import (
	"time"

	"github.com/google/uuid"
)

type BaseModel struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key"`
	CreatedAt time.Time
	UpdatedAt time.Time
}
type User struct {
	BaseModel
	FirstName  string
	MiddleName string
	SecondName string
	Email      string `gorm:"column:email"`
	Phone      string `gorm:"column:phone"`
	TelegramId string `gorm:"index;column:telegram_id"`
}
