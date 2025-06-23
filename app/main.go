package main

import (
	"app/main.go/internal/config"
	"app/main.go/internal/graceful"
	socks5proxy "app/main.go/internal/socks5Proxy"
	"context"
	"time"

	//"fmt"
	//"app/main.go/internal/graceful"
	//telegramBot "app/main.go/internal/telegram"
	"app/main.go/internal/utils/logger/handlers/slogpretty"
	//"context"

	"log/slog"
	"os"
	//"time"
	inMemory "app/main.go/internal/cache/inMemory"
	//deepseek "app/main.go/internal/deepseek"
	//openai "app/main.go/internal/openai"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

var Version = "dev"

func main() {
	cfg := config.MustLoad()

	log := setupLogger(cfg.Env)

	log.Info(
		"starting l2walker-proxy",
		slog.String("env", cfg.Env),
		slog.String("version", Version),
	)
	log.Debug("debug messages are enabled")

	
	// inMemoryCache := inMemory.NewInMemoryRepository()
	// AIBot := deepseek.NewClient(log, cfg, inMemoryCache)
	// //AIBot := openai.NewClient(log, cfg, inMemoryCache)
	// tgBot := telegramBot.New(log, cfg, AIBot)
	inMemoryXorKeyCache := inMemory.NewXorKeyInMemoryCache()
	socks5proxy := socks5proxy.New(log, cfg, inMemoryXorKeyCache)

	maxSecond := 15 * time.Second
	waitShutdown := graceful.GracefulShutdown(
		context.Background(),
		maxSecond,
		map[string]graceful.Operation{
			// "http": func(ctx context.Context) error {
			// 	return httpServer.Shutdown(ctx)
			// },
			// "tgBot": func(ctx context.Context) error {
			// 	return tgBot.Shutdown(ctx)
			// },
			"socks5proxy": func(ctx context.Context) error {
				return socks5proxy.Shutdown(ctx)
			},
		},
		log,
	)
	// go tgBot.Update(60)
	// go httpServer.Listen()
	go socks5proxy.Start()
	<-waitShutdown
	
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = setupPrettySlog()
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	default: // If env config is invalid, set prod settings by default due to security
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return log
}

func setupPrettySlog() *slog.Logger {
	opts := slogpretty.PrettyHandlerOptions{
		SlogOpts: &slog.HandlerOptions{
			Level: slog.LevelDebug,
		},
	}

	handler := opts.NewPrettyHandler(os.Stdout)

	return slog.New(handler)
}
