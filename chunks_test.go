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
	"crypto/rand"
	"reflect"
	"testing"
)

func TestChunks_NewChunks(t *testing.T) {
	chunksCount := uint16(3)
	remainder := uint16(0)

	payload := make([]byte, defaultChunkSize*chunksCount-remainder)

	count, err := rand.Read(payload)

	if err != nil {
		t.Fatal("cannot read random")
	}

	t.Log("Readed random:", count)

	chunksWithRemainder, err := NewChunks().SetData(payload, defaultChunkSize)

	if err != nil {
		t.Fatal(err)
	}

	strChunks := chunksWithRemainder.SerializeB64()

	readedChunks := &Chunks{}

	for i := 0; i < len(strChunks); i++ {
		err = readedChunks.ReadB64Chunk(strChunks[i])
		if err != nil {
			t.Fatal("cannot parse frame")
		}
	}

	result := make([]byte, 0)
	for i := 0; i < len(readedChunks.data); i++ {
		result = append(result, readedChunks.data[i]...)
	}
	uncompressedResult, err := uncompress(result)

	if err != nil {
		t.Fatal("cannot uncompress data", err)
	}

	if !reflect.DeepEqual(payload, uncompressedResult) {
		t.Fatal("mismatch marshalled data")
	}
}
