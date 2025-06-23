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

	if err := t.Decode2(ctx, data); err != nil {
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
		// for i, j := 0, len(savedBytes)-1; i < j; i, j = i+1, j-1 {
		// 	savedBytes[i], savedBytes[j] = savedBytes[j], savedBytes[i]
		// }

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
func Encrypt(raw []byte, key_cs []byte, size int) {
	temp := 0
	for i := 0; i < size; i++ {
		temp2 := int(raw[i] & 0xFF)
		raw[i] = byte(temp2 ^ int(key_cs[i&7])&0xFF ^ temp)
		temp = int(raw[i])
	}
	old := int64(key_cs[0] & 0xFF)
	old |= int64(key_cs[1]) << 8 & 0xFF00
	old |= int64(key_cs[2]) << 16 & 0xFF0000
	old |= int64(key_cs[3]) << 24 & 0xFF000000
	old += int64(size)
	key_cs[0] = byte(old & 0xFF)
	key_cs[1] = byte(old >> 8 & 0xFF)
	key_cs[2] = byte(old >> 16 & 0xFF)
	key_cs[3] = byte(old >> 24 & 0xFF)
}

/*// Decode (Server -> Client)
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
		i1 := int(data[k]) & 0xFF
		data[k] = byte(i1 ^ int(keySC[j])&0xFF ^ i)
		j++
		i = i1
		if j > 7 {
			j = 0
		}
	}

	// Update KeySC
	l := uint64(keySC[0])&0xFF |
		uint64(keySC[1])<<8&0xFF00 |
		uint64(keySC[2])<<16&0xFF0000 |
		uint64(keySC[3])<<24&0xFF000000 |
		uint64(keySC[4])<<32&0xFF00000000 |
		uint64(keySC[5])<<40&0xFF0000000000 |
		uint64(keySC[6])<<48&0xFF000000000000 |
		uint64(keySC[7])<<56&0xFF00000000000000
	l += uint64(len(data))

	keySC[0] = byte(l & 0xFF)
	keySC[1] = byte(l >> 8 & 0xFF)
	keySC[2] = byte(l >> 16 & 0xFF)
	keySC[3] = byte(l >> 24 & 0xFF)
	keySC[4] = byte(l >> 32 & 0xFF)
	keySC[5] = byte(l >> 40 & 0xFF)
	keySC[6] = byte(l >> 48 & 0xFF)
	keySC[7] = byte(l >> 56 & 0xFF)

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
}*/

func (t *TrafficLogger) Decode(ctx context.Context, inputData []byte) error {
	op := "Decode()"
	log := t.logger.With(
		slog.String("Op", op),
	)

	i := 0
	j := 0

	input := make([]byte, len(inputData)-2)
	copy(input, inputData[2:])

	xorKeys, err := t.la2ProtocolData.xorKeysCache.Get(ctx, t.Conn.LocalAddr().String())
	if err != nil {
		return err
	}

	log.Debug(
		"Get xorKeysCache",
		slog.String("DecodeKey", hex.EncodeToString(xorKeys.DecodeXorKey)),
		slog.String("EncodeKey", hex.EncodeToString(xorKeys.EncodeXorKey)),
		slog.String("Encoded Data", hex.EncodeToString(input)),
	)

	key_sc := make([]byte, len(xorKeys.DecodeXorKey))
	copy(key_sc, xorKeys.DecodeXorKey)

	if len(key_sc) == 0 {
		return fmt.Errorf("keySC length is 0")
	}

	size := len(input)

	for k := 0; k < size; k++ {
		i1 := int(input[k] & 0xFF)
		input[k] = byte(i1 ^ int(key_sc[j])&0xFF ^ i)
		i = i1
		j++
		if j > 7 {
			j = 0
		}
	}
	l := int64(key_sc[0] & 0xFF)
	l |= int64(key_sc[1]) << 8 & 0xFF00
	l |= int64(key_sc[2]) << 16 & 0xFF0000
	l |= int64(key_sc[3]) << 24 & 0xFF000000
	l += int64(size)
	key_sc[0] = byte(l & 255)
	key_sc[1] = byte(l >> 8 & 255)
	key_sc[2] = byte(l >> 16 & 255)
	key_sc[3] = byte(l >> 24 & 255)

	updatedXorKeys := XorKeys{EncodeXorKey: xorKeys.EncodeXorKey, DecodeXorKey: key_sc}

	err = t.la2ProtocolData.xorKeysCache.Save(ctx, t.Conn.LocalAddr().String(), updatedXorKeys)
	if err != nil {
		return err
	}

	log.Debug(
		"Updated xorKeysCache",
		slog.String("DecodeKey", hex.EncodeToString(updatedXorKeys.DecodeXorKey)),
		slog.String("EncodeKey", hex.EncodeToString(updatedXorKeys.EncodeXorKey)),
		slog.String("Decoded Data Length", strconv.Itoa(len(input))),
		slog.String("Decoded Data", hex.EncodeToString(input)),
	)

	return nil
}

// reverseSlice reverses the order of elements in the provided byte slice.
// It takes a slice of bytes as input and modifies it in place.
// The function uses a for loop to iterate over the slice and swap elements from the beginning and end of the slice.
// The loop continues until the middle of the slice is reached.
// During each iteration, the elements at positions i and j are swapped.
func reverseSlice(slice []byte) {
	for i, j := 0, len(slice)-1; i < j; i, j = i+1, j-1 {
		slice[i], slice[j] = slice[j], slice[i]
	}
}
