package telegramBot

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"log/slog"

	"app/main.go/internal/utils/logger/sl"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type sendFunction func(inputMsg *tgbotapi.Message, replyText string) error

func (bot *Bot) defaultHandler(ctx context.Context, update *tgbotapi.Update, sendFunc sendFunction) {
	op := "bot.defaultHandler"
	log := bot.log.With(
		slog.String("op", op),
	)
	log.Debug("input message",
		slog.String("user id", strconv.FormatInt(update.Message.From.ID, 10)),
		slog.String("user name", update.Message.From.UserName),
		slog.String("first name", update.Message.From.FirstName),
		slog.String("last name", update.Message.From.LastName),
		slog.String("message id", strconv.Itoa(update.Message.MessageID)),
	)
	bot.tgbot.Send(tgbotapi.NewChatAction(update.FromChat().ID, tgbotapi.ChatTyping))
	ctxTimeout, cancel := context.WithTimeout(ctx, bot.cfg.BotConfig.AI.GetTimeout())
	defer cancel()

	response, err := bot.AIBot.ProcessMessage(
		ctxTimeout,
		update.Message.From.ID,
		bot.textFilter(update.Message.Text),
	)
	if err != nil {
		sl.Err(err)
		log.Error("failed to process message with AI", sl.Err(err))
	}

	log.Debug("Got response from AI", slog.String("response", response))

	err = sendFunc(update.Message, response)
	if err != nil {
		log.Error("failed to send response to user", sl.Err(err))
	} else {
		log.Debug("Sent response to user")
	}

}

func (bot *Bot) stubHandler(ctx context.Context, update *tgbotapi.Update) {
	op := "bot.handleStub"
	log := bot.log.With(
		slog.String("op", op),
	)
	select {
	case <-ctx.Done():
		return
	default:
		log.Info("input message",
			slog.String("user id", strconv.FormatInt(update.Message.From.ID, 10)),
			slog.String("user name", update.Message.From.UserName),
			slog.String("first name", update.Message.From.FirstName),
			slog.String("last name", update.Message.From.LastName),
			slog.String("message id", strconv.Itoa(update.Message.MessageID)),
		)
	}

}

func (bot *Bot) commandHandler(ctx context.Context, update *tgbotapi.Update, sendFunc sendFunction) error {
	op := "bot.commandHandle"
	// Extract the command from the Message.
	log := bot.log.With(
		slog.String("op", op),
	)

	msg := update.Message

	switch update.Message.Command() {
	case "setsystempromt":
		replyText := ""
		isAdmin, err := bot.isAdmin(update.Message)

		log.Debug("setsystempromt",
			slog.String("user name", update.Message.From.UserName),
			slog.String("message", update.Message.Text),
			slog.String("is admin", strconv.FormatBool(isAdmin)),
		)

		if err != nil {
			return fmt.Errorf("bot.commandHandle: %w", err)
		}

		if isAdmin {

			bot.cfg.BotConfig.AI.SystemRolePromt = strings.TrimPrefix(
				update.Message.Text, "/setsystempromt ")

			err = bot.cfg.Write()
			if err != nil {
				return fmt.Errorf("bot.commandHandle: %w", err)
			}

			replyText = "👍 System role promt changed 👍"
			err = bot.sendReplyMessage(update.Message, replyText)
			if err != nil {
				return fmt.Errorf("tgbot.commandHandle: %w", err)
			}
		}

	case "getsystempromt":

		replyText := ""
		isAdmin, err := bot.isAdmin(update.Message)

		log.Debug("getsystempromt",
			slog.String("user name", update.Message.From.UserName),
			slog.String("message", update.Message.Text),
			slog.String("is admin", strconv.FormatBool(isAdmin)),
		)

		if err != nil {
			return fmt.Errorf("tgbot.commandHandle: %w", err)
		}

		if isAdmin {

			replyText = bot.cfg.BotConfig.AI.SystemRolePromt

			err = bot.sendReplyMessage(update.Message, replyText)
			if err != nil {
				return fmt.Errorf("tgbot.commandHandle: %w", err)
			}
		}

	case "askbot":
		ctxTimeout, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		response, err := bot.AIBot.ProcessMessage(
			ctxTimeout,
			update.Message.From.ID,
			bot.textFilter(update.Message.Text),
		)
		if err != nil {
			sl.Err(err)
		}

		err = sendFunc(update.Message, response)
		if err != nil {
			sl.Err(err)
		}

	case "start":
		replyText := fmt.Sprintf("Hi, %s! Ask your questions.", msg.From.UserName)
		err := bot.sendMessage(msg, replyText)
		if err != nil {
			return fmt.Errorf("tgbot.commandHandle: %w", err)
		}

	default:
		replyText := "I don't know this command"
		err := bot.sendReplyMessage(msg, replyText)
		if err != nil {
			return fmt.Errorf("tgbot.commandHandle: %w", err)
		}
	}

	return nil
}

// textFilter processes the input message by removing the "/askbot" prefix
// and filtering out words that start with "@". This function is used to
// clean up user input before processing it further.
//
// Parameters:
//   - msg: A string containing the original message text.
//
// Returns:
//
//	A string with the "/askbot" prefix removed and any words starting with "@" filtered out.
func (bot *Bot) textFilter(msg string) string {

	msgText := strings.TrimPrefix(msg, "/askbot ")

	words := strings.Split(msgText, " ")
	var filteredWords []string
	for _, word := range words {
		if !strings.HasPrefix(word, "@") {
			filteredWords = append(filteredWords, word)
		}
	}
	msgText = strings.Join(filteredWords, " ")
	return msgText
}
