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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"testing"
)

const (
	testPassphrase = "My dummy AES256 password 0123456"
	opCodeTest1    = 1
	opCodeTest2    = 1000
	opCodeTest3    = 65535
)

type DummyEncryptorDecryptor struct {
	key   []byte
	nonce []byte
}

func NewDummyEncryptorDecryptor() *DummyEncryptorDecryptor {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	return &DummyEncryptorDecryptor{
		key:   []byte(testPassphrase),
		nonce: nonce,
	}
}

func (ed *DummyEncryptorDecryptor) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ed.key)

	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

	return aesGCM.Seal(nil, ed.nonce, data, nil), nil
}

func (ed *DummyEncryptorDecryptor) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ed.key)
	if err != nil {
		panic(err.Error())
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	return aesGCM.Open(nil, ed.nonce, data, nil)
}

func TestAirGap_CreateMessage(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("cannot generate private key")
	}

	pubKeySerialized := elliptic.MarshalCompressed(elliptic.P256(), privKey.X, privKey.Y)

	airGap := NewAirGap(VersionDefault, pubKeySerialized)

	ed := NewDummyEncryptorDecryptor()

	airGap.SetEncryptorDecryptor(ed)

	opMessage := airGap.CreateMessage().
		AddOperation(opCodeTest1, []byte(`{"key": "secret message 1"}`)).
		AddOperation(opCodeTest2, []byte(`{"key": "secret message 2"}`)).
		AddOperation(opCodeTest3, []byte(`{"key": "secret message 3"}`))

	serializedChunks, err := opMessage.MarshalB64Chunks()
	if err != nil {
		t.Fatal(err)
	}
	serializedChunks2, err := opMessage.MarshalB64Chunks()
	if err != nil {
		t.Fatal(err)
	}
	serializedChunks3, err := opMessage.MarshalB64Chunks()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(serializedChunks)
	t.Log(serializedChunks2)
	t.Log(serializedChunks3)
	if err != nil {
		t.Fatal("cannot serialize Chunks")
	}

	// t.Log(serializedChunks)

	unserializedChunks := &Chunks{}

	for i := range serializedChunks {
		_, err = unserializedChunks.ReadB64Chunk(serializedChunks[i])
		if err != nil {
			t.Fatal(err)
		}
	}

	chunksData := unserializedChunks.Data()

	t.Log(chunksData)
	unserializedMessage, err := airGap.Unmarshal(chunksData)

	if err != nil {
		t.Log(err)
		t.Fatal("cannot unserialize Chunks")
	}

	t.Log(unserializedMessage)
}
