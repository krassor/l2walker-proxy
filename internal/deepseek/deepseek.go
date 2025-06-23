package deepseek

import (
	"context"
	"fmt"
	"log/slog"

	"app/main.go/internal/config"
	"app/main.go/internal/utils/logger/sl"

	dsmod "github.com/cohesion-org/deepseek-go"
	"github.com/cohesion-org/deepseek-go/constants"
)

type Cache interface {
	Save(ctx context.Context, userID int64, history []interface{}) error
	Get(ctx context.Context, userID int64) ([]interface{}, error)
	Delete(ctx context.Context, id int64) error
}

type DeepSeek struct {
	logger          *slog.Logger
	config          *config.Config
	Client          *dsmod.Client
	cache           Cache
	shutdownChannel chan struct{}
	ctx             context.Context
	cancel          context.CancelFunc
}

func NewClient(
	logger *slog.Logger,
	config *config.Config,
	cache Cache,
) *DeepSeek {

	op := "deepseek.NewClient()"
	log := logger.With(
		slog.String("op", op),
	)

	aiToken := config.BotConfig.AI.AIApiToken

	ctx, cancel := context.WithCancel(context.Background())

	client := dsmod.NewClient(aiToken, config.BotConfig.AI.BaseURL)

	log.Info("Creating deepseek client")

	return &DeepSeek{
		logger:          logger,
		config:          config,
		Client:          client,
		cache:           cache,
		shutdownChannel: make(chan struct{}),
		ctx:             ctx,
		cancel:          cancel,
	}
}

func (ds *DeepSeek) ProcessMessage(ctx context.Context, userID int64, message string) (string, error) {
	op := "deepseek.ProcessMessage()"
	log := ds.logger.With(
		slog.String("op", op),
		slog.Int64("userID", userID),
	)

	log.Debug("input message", slog.String("message", message))

	// Получаем историю сообщений из cache
	history, err := ds.cache.Get(ctx, userID)
	if err != nil {
		sl.Err(err)
	}

	// Добавляем новое сообщение
	history = append(history, dsmod.ChatCompletionMessage{
		Role:    constants.ChatMessageRoleUser,
		Content: message,
	})

	// Обрезаем историю если превышен лимит сообщений
	history = ds.truncateHistory(history)

	// Convert history to []dsmod.ChatCompletionMessage
	messages := make([]dsmod.ChatCompletionMessage, len(history))
	for i, msg := range history {
		if chatMsg, ok := msg.(dsmod.ChatCompletionMessage); ok {
			messages[i] = chatMsg
		}
	}

	log.Debug("created chat completion request", slog.Any("messages", messages))

	resp, err := ds.Client.CreateChatCompletion(
		ctx,
		&dsmod.ChatCompletionRequest{
			// TODO: вынести в параметры конфигурации openai
			Model:    ds.config.BotConfig.AI.ModelName,
			Messages: messages,
		},
	)

	if err != nil {
		log.Error("error creating chat completion request", slog.String("error", err.Error()))
		return "", fmt.Errorf("%w", err)
	}

	log.Debug("received chat completion response", slog.Any("response", resp))

	//Save response from openai GPT bot as an assistant response
	msg := dsmod.ChatCompletionMessage{
		Role:    constants.ChatMessageRoleAssistant,
		Content: resp.Choices[0].Message.Content,
	}
	// Добавляем ответ в кэш
	history = append(history, msg)
	err = ds.cache.Save(ctx, userID, history)
	if err != nil {
		log.Error("", slog.String("error", err.Error()))
	}

	return resp.Choices[0].Message.Content, nil
}

// func (ds *DeepSeek) truncateHistory(history []interface{}) []interface{} {

// 	if len(history) > 11 {
// 		return history[len(history)-6:]
// 	}

// 	if history[0].(dsmod.ChatCompletionMessage).Role != constants.ChatMessageRoleSystem {
// 		//Восстанавливаем системный промт в [0] сообщении
// 		systemRoleMessage := make([]interface{}, 1)
// 		systemRoleMessage[0] = dsmod.ChatCompletionMessage{
// 			Role:    constants.ChatMessageRoleSystem,
// 			Content: ds.config.BotConfig.AI.SystemRolePromt,
// 		}
// 		//Добавляем системное сообщение вперед
// 		history = append(systemRoleMessage, history...)
// 	}

// 	return history
// }

func (ds *DeepSeek) truncateHistory(history []interface{}) []interface{} {
    const (
        maxHistoryLength = 10
        keepLastN        = 5
    )

    // Добавление системного промпта
    if len(history) == 0 || getMessageRole(history[0]) != constants.ChatMessageRoleSystem {
        systemMsg := createSystemMessage(ds.config.BotConfig.AI.SystemRolePromt)
        history = prependSystemMessage(history, systemMsg)
    }

    // Обрезка истории
    if len(history) > maxHistoryLength {
        keepFrom := len(history) - keepLastN
        if keepFrom < 1 { // Всегда оставляем системное сообщение
            keepFrom = 1
        }
        return append([]interface{}{history[0]}, history[keepFrom:]...)
    }

    return history
}

// Вспомогательные функции
func getMessageRole(msg interface{}) string {
    if m, ok := msg.(dsmod.ChatCompletionMessage); ok {
        return m.Role
    }
    return ""
}

func createSystemMessage(prompt string) interface{} {
    return dsmod.ChatCompletionMessage{
        Role:    constants.ChatMessageRoleSystem,
        Content: prompt,
    }
}

func prependSystemMessage(history []interface{}, systemMsg interface{}) []interface{} {
    if len(history) > 0 && getMessageRole(history[0]) == constants.ChatMessageRoleSystem {
        return history
    }
    return append([]interface{}{systemMsg}, history...)
}

func (ds *DeepSeek) Shutdown(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("force exit AI client: %w", ctx.Err())
		default:
			ds.cancel()
			return nil
		}
	}
}
