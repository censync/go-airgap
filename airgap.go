// Copyright 2022 Dmitry Mandrika
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package go_airgap

import (
	"bytes"
	"errors"
)

const (
	VersionDefault         = 1
	compressedPubKeySize   = 33
	airGapMessagesOffset   = 1 + compressedPubKeySize // version(1) + pub_key(33)
	operationPayloadOffset = 6                        // op_code(2) + op_size(4)
)

type AirGap struct {
	// version of protocol
	version uint8
	// instanceId compressed public key for device pairing
	instanceId []byte

	chunkSize int

	ed EncryptorDecryptor
}

// Encryptor implements encryption method for chunks
type Encryptor interface {
	Encrypt(data []byte) ([]byte, error)
}

// Decryptor implements decryption method for chunks
type Decryptor interface {
	Decrypt(data []byte) ([]byte, error)
}

// EncryptorDecryptor provides encryption and decryption methods
// for airgap session security
type EncryptorDecryptor interface {
	Encryptor
	Decryptor
}

type Message struct {
	Version    uint8
	InstanceId []byte
	Payload    []*OpPayload
	chunkSize  int
	e          Encryptor
}

// OpPayload is operation payload data
type OpPayload struct {
	// OpCode - operation code
	OpCode uint16
	Size   uint32
	Data   []byte
}

// NewAirGap initiates a new AirGap instance with secp256k1 serialized compressed public key
func NewAirGap(version uint8, instanceId []byte) *AirGap {
	//var compressedPubKey []byte
	if instanceId == nil || len(instanceId) != compressedPubKeySize {
		panic("incorrect instance pub key size")
	}

	//copy(compressedPubKey, instanceId)
	return &AirGap{
		version:    version,
		instanceId: instanceId,
		chunkSize:  defaultChunkSize,
	}
}

func (a *AirGap) SetEncryptorDecryptor(ed EncryptorDecryptor) *AirGap {
	a.ed = ed
	return a
}

func (a *AirGap) SetVersion(version uint8) {
	a.version = version
}

func (a *AirGap) SetChunkSize(chunkSize int) {
	a.chunkSize = chunkSize
}

func (a *AirGap) ChunkSize() int {
	return a.chunkSize
}

// CreateMessage initiates new builder for AirGap messages batch
func (a *AirGap) CreateMessage() *Message {
	if a.instanceId == nil {
		panic("instance id is not defined")
	}
	return &Message{
		Version:    a.version,
		InstanceId: a.instanceId,
		chunkSize:  a.chunkSize,
		e:          a.ed,
	}
}

func (m *Message) AddOperation(opCode uint16, data []byte) *Message {
	m.Payload = append(m.Payload, &OpPayload{
		OpCode: opCode,
		Size:   uint32(len(data)),
		Data:   data,
	})
	return m
}

func (m *Message) Marshal() ([]byte, error) {
	result := make([]byte, 0)
	result = append(result, m.Version)
	result = append(result, m.InstanceId[:]...)
	for i := range m.Payload {
		// Allocate memory for serialized chunk
		payload := make([]byte, operationPayloadOffset+m.Payload[i].Size)

		// Serialize operation code
		payload[0] = byte(m.Payload[i].OpCode >> 8)
		payload[1] = byte(m.Payload[i].OpCode)

		// Serialize chunk size
		payload[2] = byte(m.Payload[i].Size >> 24)
		payload[3] = byte(m.Payload[i].Size >> 16)
		payload[4] = byte(m.Payload[i].Size >> 8)
		payload[5] = byte(m.Payload[i].Size)

		// Serialize payload
		copy(payload[operationPayloadOffset:], m.Payload[i].Data)
		result = append(result, payload...)
	}

	if m.e != nil {
		return m.e.Encrypt(result)
	}
	return result, nil
}

func (m *Message) MarshalB64Chunks() ([]string, error) {
	serializedMessages, err := m.Marshal()
	if err != nil {
		return nil, err
	}

	result, err := NewChunks(serializedMessages, m.chunkSize)

	if err != nil {
		return nil, err
	}

	return result.SerializeB64(), nil
}

func (a *AirGap) Unmarshal(data []byte) (*Message, error) {
	var err error

	if a.ed != nil {
		data, err = a.ed.Decrypt(data)
		if err != nil {
			return nil, err
		}
	}
	version := data[0]
	instanceId := data[1:airGapMessagesOffset]

	if version != a.version {
		if version < a.version {
			return nil, errors.New("go-airgap message version less than supported")
		}

		if version > a.version {
			return nil, errors.New("go-airgap message version greater than supported")
		}
	}

	if !bytes.Equal(a.instanceId, instanceId) {
		return nil, errors.New("go-airgap message has incorrect instance")
	}
	message := a.CreateMessage()

	bytesReaded := airGapMessagesOffset

	for iter := bytesReaded; iter < len(data); iter += bytesReaded {
		opCode := uint16(data[iter+1]) | uint16(data[iter])<<8
		size := uint32(data[iter+5]) | uint32(data[iter+4])<<8 | uint32(data[iter+3])<<16 | uint32(data[iter+2])<<24
		bytesReaded = operationPayloadOffset + int(size)
		message.AddOperation(opCode, data[iter+6:iter+bytesReaded])

	}

	return message, nil
}
