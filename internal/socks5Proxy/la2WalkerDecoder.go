package socks5proxy

import (
	"context"
	"encoding/hex"
	"log/slog"
)

func (t *TrafficLogger) DataProcessing(ctx context.Context, logger *slog.Logger, data []byte) error {
	op := "DataProcessing()"
	log := logger.With(
		slog.String("Op", op),
	)

	// Анализируем и модифицируем данные
	ok, foundedXorKey := findXorKey(data, t.logger)
	if ok {
		err := t.la2ProtocolData.xorKeysCache.Save(
			context.TODO(),
			t.Conn.LocalAddr().String(),
			XorKeys{EncodeXorKey: foundedXorKey, DecodeXorKey: foundedXorKey},
		)
		if err != nil {
			return err
		}
		log.Info(
			"XOR Key stored",
			slog.String("LocalAddr", t.Conn.LocalAddr().String()),
			slog.String("RemoteAddr", t.Conn.RemoteAddr().String()),
			slog.String("XOR Key", hex.EncodeToString(foundedXorKey)),
		)
	}

	return nil
}

// analyzeAndModifyPacket анализирует пакет и выполняет требуемые модификации
func findXorKey(data []byte, logger *slog.Logger) (bool, []byte) {
	op := "findXorKey()"
	log := logger.With(
		slog.String("op", op),
	)
	if len(data) >= 12 && data[2] == 0x00 && data[3] == 0x01 {
		savedBytes := make([]byte, 8)
		copy(savedBytes, data[4:12])

		// Реверсируем байты
		for i, j := 0, len(savedBytes)-1; i < j; i, j = i+1, j-1 {
			savedBytes[i], savedBytes[j] = savedBytes[j], savedBytes[i]
		}

		log.Info("found XOR Key", slog.String("xorKey", hex.EncodeToString(savedBytes)))

		// Создаем модифицированный пакет
		// modified := make([]byte, len(data))
		// copy(modified, data)
		// copy(modified[4:12], savedBytes)

		return true, savedBytes
	}
	return false, nil
}