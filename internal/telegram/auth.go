package telegramBot

import (
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

func (bot *Bot) isAdmin(msg *tgbotapi.Message) (bool, error) {
	result := false

	for _, admin := range bot.cfg.BotConfig.Admins {
		if admin == msg.From.UserName {
			result = true
			break
		}
	}

	return result, nil
}
