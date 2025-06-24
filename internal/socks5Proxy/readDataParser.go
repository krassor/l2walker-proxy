package socks5proxy

import (
	"fmt"
)

type packetSay2 struct {
	ObjectID    uint32
	MessageType uint32
	SenderName  string
	MessageText string
}

func parsePacketSay2 (inputData []byte) (*packetSay2, error) {
	if len(inputData) < 8 {
		return nil, fmt.Errorf("длина данных меньше 8 байт")
	}

	msg := &packetSay2{}

	// Объект ID (4 байта)
	objectIDBytes := inputData[0:4]
	reverseSlice(objectIDBytes)	
	msg.ObjectID = uint32(objectIDBytes[0])<<24 | uint32(objectIDBytes[1])<<16 | uint32(objectIDBytes[2])<<8 | uint32(objectIDBytes[3])

	// Тип сообщения (4 байта)
	msgTypeBytes := inputData[4:8]
	reverseSlice(msgTypeBytes)
	msg.MessageType = uint32(msgTypeBytes[0])<<24 | uint32(msgTypeBytes[1])<<16 | uint32(msgTypeBytes[2])<<8 | uint32(msgTypeBytes[3])

	// Имя отправителя (Unicode строка, заканчивается на 0x00 0x00)
	nameStart := 8
	var nameEnd int
	for i := nameStart; i+1 < len(inputData); i += 2 {
		if inputData[i] == 0x00 && inputData[i+1] == 0x00 {
			nameEnd = i
			break
		}
	}
	if nameEnd == 0 || nameEnd <= nameStart {
		return nil, fmt.Errorf("строка имени не завершена")
	}
	nameBytes := inputData[nameStart:nameEnd]
	reverseSlice(nameBytes)
	msg.SenderName = string(nameBytes)

	// Сообщение (Unicode строка, заканчивается на 0x00 0x00)
	msgStart := nameEnd + 2 // пропускаем 0x00 0x00
	var msgEnd int
	for i := msgStart; i+1 < len(inputData); i += 2 {
		if inputData[i] == 0x00 && inputData[i+1] == 0x00 {
			msgEnd = i
			break
		}
	}
	if msgEnd == 0 || msgEnd <= msgStart {
		return nil, fmt.Errorf("строка сообщения не завершена")
	}
	msgBytes := inputData[msgStart:msgEnd]
	reverseSlice(msgBytes)
	msg.MessageText = string(msgBytes)

	return msg, nil
}