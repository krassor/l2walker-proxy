package socks5proxy

import (
	"app/main.go/internal/config"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	nativeLog "log"
	"log/slog"
	"net"
	"os"

	"github.com/armon/go-socks5"
)

type Cache interface {
	Save(ctx context.Context, ipPort string, xorKeys XorKeys) error
	Get(ctx context.Context, ipPort string) (XorKeys, error)
	Delete(ctx context.Context, ipPort string) error
}

type XorKeys struct {
	EncodeXorKey []byte
	DecodeXorKey []byte
}

type socks5proxy struct {
	config          *config.Config
	log             *slog.Logger
	socks5proxy     *socks5.Server
	shutdownChannel chan struct{}
	ctx             context.Context
	cancel          context.CancelFunc
	LoggingDialer   LoggingDialer
}

// LoggingDialer создает соединения с логированием
type LoggingDialer struct {
	logger        *slog.Logger
	trafficLogger *TrafficLogger
}

// TrafficLogger реализует net.Conn для логирования трафика
type TrafficLogger struct {
	net.Conn
	logger          *slog.Logger
	buf             bytes.Buffer
	la2ProtocolData la2ProtocolData
}

type la2ProtocolData struct {
	xorKeysCache Cache
}

func (d *LoggingDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	d.trafficLogger.Conn = conn
	d.trafficLogger.logger = d.logger
	return d.trafficLogger, nil
}

func New(logger *slog.Logger, config *config.Config, xorKeysCache Cache) *socks5proxy {
	// Настраиваем логгер
	op := "NewSocks5Proxy()"
	log := logger.With(
		slog.String("op", op),
	)

	socks5Logger := nativeLog.New(os.Stdout, op, nativeLog.LstdFlags)
	trafficLogger := &TrafficLogger{
		logger: log,
		la2ProtocolData: la2ProtocolData{
			xorKeysCache: xorKeysCache,
		},
	}
	LoggingDialer := &LoggingDialer{
		logger:        logger,
		trafficLogger: trafficLogger,
	}

	// Конфигурация SOCKS5 сервера
	conf := &socks5.Config{
		Dial:   LoggingDialer.Dial,
		Logger: socks5Logger,
	}

	server, err := socks5.New(conf)
	if err != nil {
		log.Error("Failed to create SOCKS5 server", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &socks5proxy{
		config:          config,
		log:             logger,
		socks5proxy:     server,
		shutdownChannel: make(chan struct{}),
		ctx:             ctx,
		cancel:          cancel,
	}
}

func (t *TrafficLogger) Read(b []byte) (int, error) {
	op := "TrafficLogger.Read()"
	log := t.logger.With(
		slog.String("op", op),
	)

	n, err := t.Conn.Read(b)
	if err != nil {
		return 0, err
	}

	if n > 0 {
		data := b[:n]
		log.Debug("Received data", "length", n, "data", hex.EncodeToString(data))

		//Запускаем анализ данных
		if err := t.DataProcessing(context.TODO(), log, data); err != nil {
			return 0, err
		}

		// Записываем данные в буфер для дальнейшей передачи
		if _, err := t.buf.Write(data); err != nil {
			return 0, err
		}
	}
	return n, nil
}

func (t *TrafficLogger) Write(b []byte) (int, error) {
	t.logger.Debug("Sending data", "length", len(b), "data", hex.EncodeToString(b))
	return t.Conn.Write(b)
}

func (s *socks5proxy) Start() {
	// Настраиваем логгер
	op := "Start()"
	log := s.log.With(
		slog.String("op", op),
	)

	log.Info(
		"starting SOCKS5 proxy server on",
		slog.String("address", s.config.Socks5Proxy.Address),
		slog.String("port", s.config.Socks5Proxy.Port),
	)

	if err := s.socks5proxy.ListenAndServe(
		"tcp",
		fmt.Sprintf("%s:%s", s.config.Socks5Proxy.Address, s.config.Socks5Proxy.Port),
	); err != nil {
		log.Error("Failed to start SOCKS5 server", "error", err)
		os.Exit(1)
	}
}

func (s *socks5proxy) Shutdown(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("force exit socks5Proxy: %w", ctx.Err())
		default:
			close(s.shutdownChannel)
			s.cancel()
			return nil
		}
	}
}
