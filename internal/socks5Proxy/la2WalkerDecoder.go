package socks5proxy

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
)

func (t *TrafficLogger) DataProcessing(ctx context.Context, logger *slog.Logger, data []byte) error {
	op := "DataProcessing()"
	log := logger.With(
		slog.String("Op", op),
	)

	// Анализируем и модифицируем данные
	ok, foundedXorKey := findFirstXorKey(data, t.logger)
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
			"FirstXorKey stored",
			slog.String("LocalAddr", t.Conn.LocalAddr().String()),
			slog.String("RemoteAddr", t.Conn.RemoteAddr().String()),
			slog.String("FirstXorKey", hex.EncodeToString(foundedXorKey)),
		)

		return nil
	}

	if err := t.Decode(ctx, data); err != nil {
		return err
	}

	return nil
}

// analyzeAndModifyPacket анализирует пакет и выполняет требуемые модификации
func findFirstXorKey(data []byte, logger *slog.Logger) (bool, []byte) {
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

		log.Info("found firstXorKey", slog.String("firstXorKey", hex.EncodeToString(savedBytes)))

		// Создаем модифицированный пакет
		// modified := make([]byte, len(data))
		// copy(modified, data)
		// copy(modified[4:12], savedBytes)

		return true, savedBytes
	}
	return false, nil
}

// Encrypt (Client -> Server)
func Encrypt(data []byte, keyCS []byte) {
	temp := 0
	for i := range data {
		temp2 := int(data[i])
		data[i] = byte(temp2 ^ int(keyCS[i%8]) ^ temp)
		temp = int(data[i])
	}

	// Update KeyCS
	old := uint32(keyCS[0]) |
		uint32(keyCS[1])<<8 |
		uint32(keyCS[2])<<16 |
		uint32(keyCS[3])<<24
	old += uint32(len(data))

	keyCS[0] = byte(old)
	keyCS[1] = byte(old >> 8)
	keyCS[2] = byte(old >> 16)
	keyCS[3] = byte(old >> 24)
}

// Decode (Server -> Client)
func (t *TrafficLogger) Decode(ctx context.Context, inputData []byte) error {
	op := "Decode()"
	log := t.logger.With(
		slog.String("Op", op),
	)
	var (
		i int
		j int
	)

	data := make([]byte, len(inputData)-2)
	copy(data, inputData[2:])

	xorKeys, err := t.la2ProtocolData.xorKeysCache.Get(ctx, t.Conn.LocalAddr().String())
	if err != nil {
		return err
	}

	log.Debug(
		"Get xorKeysCache",
		slog.String("DecodeKey", hex.EncodeToString(xorKeys.DecodeXorKey)),
		slog.String("EncodeKey", hex.EncodeToString(xorKeys.EncodeXorKey)),
		slog.String("Encoded Data", hex.EncodeToString(data)),
	)

	keySC := make([]byte, len(xorKeys.DecodeXorKey))
	copy(keySC, xorKeys.DecodeXorKey)

	if len(keySC) == 0 {
		return fmt.Errorf("keySC length is 0")
	}

	for k := range data {
		i1 := int(data[k])
		data[k] = byte(i1 ^ int(keySC[j]) ^ i)
		i = i1
		j++
		if j > 7 {
			j = 0
		}
	}

	// Update KeySC
	l := uint32(keySC[0]) |
		uint32(keySC[1])<<8 |
		uint32(keySC[2])<<16 |
		uint32(keySC[3])<<24
	l += uint32(len(data))

	keySC[0] = byte(l)
	keySC[1] = byte(l >> 8)
	keySC[2] = byte(l >> 16)
	keySC[3] = byte(l >> 24)

	updatedXorKeys := XorKeys{EncodeXorKey: xorKeys.EncodeXorKey, DecodeXorKey: keySC}

	err = t.la2ProtocolData.xorKeysCache.Save(ctx, t.Conn.LocalAddr().String(), updatedXorKeys)
	if err != nil {
		return err
	}

	log.Debug(
		"Updated xorKeysCache",
		slog.String("DecodeKey", hex.EncodeToString(updatedXorKeys.DecodeXorKey)),
		slog.String("EncodeKey", hex.EncodeToString(updatedXorKeys.EncodeXorKey)),
		slog.String("Decoded Data Length", strconv.Itoa(len(data))),
		slog.String("Decoded Data", hex.EncodeToString(data)),
	)

	return nil
}
