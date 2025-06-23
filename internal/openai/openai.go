package openai

import (
	"context"
	"fmt"
	"log/slog"

	"app/main.go/internal/config"
	"app/main.go/internal/utils/logger/sl"

	openai "github.com/sashabaranov/go-openai"
)

type Cache interface {
	Save(ctx context.Context, userID int64, history []interface{}) error
	Get(ctx context.Context, userID int64) ([]interface{}, error)
	Delete(ctx context.Context, id int64) error
}

type OpenAI struct {
	logger          *slog.Logger
	config          *config.Config
	Client          *openai.Client
	cache           Cache
	shutdownChannel chan struct{}
	ctx             context.Context
	cancel          context.CancelFunc
}

func NewClient(
	logger *slog.Logger,
	config *config.Config,
	cache Cache,
) *OpenAI {

	op := "openai.NewClient()"
	log := logger.With(
		slog.String("op", op),
	)

	aiToken := config.BotConfig.AI.AIApiToken

	ctx, cancel := context.WithCancel(context.Background())

	client := openai.NewClient(aiToken)

	log.Info("Creating deepseek client")

	return &OpenAI{
		logger:          logger,
		config:          config,
		Client:          client,
		cache:           cache,
		shutdownChannel: make(chan struct{}),
		ctx:             ctx,
		cancel:          cancel,
	}
}

func (c *OpenAI) ProcessMessage(ctx context.Context, userID int64, message string) (string, error) {
	op := "openai.ProcessMessage()"
	log := c.logger.With(
		slog.String("op", op),
		slog.Int64("userID", userID),
	)
	log.Debug("start processing message")
	// Получаем историю сообщений из cache
	history, err := c.cache.Get(ctx, userID)
	if err != nil {
		sl.Err(err)
	}
	log.Debug("got history from cache")

	// Добавляем новое сообщение
	history = append(history, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleUser,
		Content: message,
	})

	// Обрезаем историю если превышен лимит сообщений
	history = c.truncateHistory(history)
	log.Debug("truncated history")

	// Convert history to []dsmod.ChatCompletionMessage
	messages := make([]openai.ChatCompletionMessage, len(history))
	for i, msg := range history {
		if chatMsg, ok := msg.(openai.ChatCompletionMessage); ok {
			messages[i] = chatMsg
		}
	}

	resp, err := c.Client.CreateChatCompletion(
		ctx,
		openai.ChatCompletionRequest{
			Model:       openai.GPT3Dot5Turbo0613,
			Messages:    messages,
			Temperature: c.config.BotConfig.AI.Temperature,
			N:           c.config.BotConfig.AI.N,
			MaxTokens:   c.config.BotConfig.AI.MaxTokens,
		},
	)
	log.Debug("got response from openai")

	if err != nil {
		return "", err
	}

	//response := fmt.Sprintf("%s\n-----------\nCompletion tokens usage: %v\nPrompt tokens usage%v\nTotal tokens usage: %v", resp.Choices[0].Message.Content, resp.Usage.CompletionTokens, resp.Usage.PromptTokens, resp.Usage.TotalTokens)

	//Save response from openai GPT bot as an assistant response
	msg := openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleAssistant,
		Content: resp.Choices[0].Message.Content,
	}
	// Добавляем ответ в кэш
	history = append(history, msg)
	err = c.cache.Save(ctx, userID, history)
	if err != nil {
		log.Error("", slog.String("error", err.Error()))
	}
	log.Debug("history saved in cache")

	return resp.Choices[0].Message.Content, nil
}

func (c *OpenAI) truncateHistory(history []interface{}) []interface{} {

	if len(history) > 11 {
		return history[len(history)-6:]
	}

	//Восстанавливаем системный промт в [0] сообщении
	systemRoleMessage := make([]interface{}, 1)
	systemRoleMessage[0] = openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleSystem,
		Content: c.config.BotConfig.AI.SystemRolePromt,
	}
	//Добавляем системное сообщение вперед
	history = append(systemRoleMessage, history...)

	return history
}

func (ds *OpenAI) Shutdown(ctx context.Context) error {
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
