// Copyright 2017, OpenCensus Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package tag

import (
	"encoding/binary"
	"fmt"
)

// KeyType defines the types of keys allowed. Currently only keyTypeString is
// supported.
type keyType byte

const (
	keyTypeString keyType = iota
	keyTypeInt64
	keyTypeTrue
	keyTypeFalse

	tagsVersionID = byte(0)
)

type encoder struct {
	buf      []byte
	writeIdx int
}

// writeKeyString writes the fieldID '0' followed
// by the key string and value string.
func (eg *encoder) writeKVString(k, v string) {
	eg.writeByte(byte(keyTypeString))
	eg.writeString(k)
	eg.writeString(v)
}

func (eg *encoder) writeKVUint64(k string, i uint64) {
	eg.writeByte(byte(keyTypeInt64))
	eg.writeString(k)
	eg.writeUint64(i)
}

func (eg *encoder) writeKVTrue(k string) {
	eg.writeByte(byte(keyTypeTrue))
	eg.writeString(k)
}

func (eg *encoder) writeKVFalse(k string) {
	eg.writeByte(byte(keyTypeFalse))
	eg.writeString(k)
}

func (eg *encoder) writeBytes(bytes []byte) {
	length := len(bytes)
	eg.growIfRequired(binary.MaxVarintLen64 + length)
	eg.writeIdx += binary.PutUvarint(eg.buf[eg.writeIdx:], uint64(length))
	copy(eg.buf[eg.writeIdx:], bytes)
	eg.writeIdx += length
}

func (eg *encoder) writeString(s string) {
	length := len(s)
	eg.growIfRequired(binary.MaxVarintLen64 + length)
	eg.writeIdx += binary.PutUvarint(eg.buf[eg.writeIdx:], uint64(length))
	copy(eg.buf[eg.writeIdx:], s)
	eg.writeIdx += length
}

func (eg *encoder) writeByte(v byte) {
	eg.growIfRequired(1)
	eg.buf[eg.writeIdx] = v
	eg.writeIdx++
}

func (eg *encoder) writeUint64(i uint64) {
	eg.growIfRequired(8)
	binary.LittleEndian.PutUint64(eg.buf[eg.writeIdx:], i)
	eg.writeIdx += 8
}

func (eg *encoder) growIfRequired(expected int) {
	if len(eg.buf)-eg.writeIdx < expected {
		tmp := make([]byte, 2*(len(eg.buf)+1)+expected)
		copy(tmp, eg.buf)
		eg.buf = tmp
	}
}

type decoder struct {
	buf     []byte
	readIdx int
}

func (eg *decoder) readByte() byte {
	b := eg.buf[eg.readIdx]
	eg.readIdx++
	return b
}

func (eg *decoder) readUint64() uint64 {
	i := binary.LittleEndian.Uint64(eg.buf[eg.readIdx:])
	eg.readIdx += 8
	return i
}

func (eg *decoder) readBytes() ([]byte, error) {
	if eg.ended() {
		return nil, fmt.Errorf("unexpected end while readBytes '%x' starting at idx '%v'", eg.buf, eg.readIdx)
	}
	length, start := binary.Uvarint(eg.buf[eg.readIdx:])
	if start <= 0 {
		return nil, fmt.Errorf("unexpected end while readBytes '%x' starting at idx '%v'", eg.buf, eg.readIdx)
	}

	start += eg.readIdx
	end := start + int(length)
	if end > len(eg.buf) {
		return nil, fmt.Errorf("malformed encoding; length: %v, upper: %v, maxLength: %v", length, end, len(eg.buf))
	}

	eg.readIdx = end
	return eg.buf[start:end], nil
}

func (eg *decoder) ended() bool {
	return eg.readIdx >= len(eg.buf)
}

func (eg *encoder) bytes() []byte {
	return eg.buf[:eg.writeIdx]
}

// Encode encodes the tag map into a []byte. It is useful to propagate
// the tag maps on wire in binary format.
func Encode(m *Map) []byte {
	enc := &encoder{buf: make([]byte, 128*len(m.m))} // TODO(jbd): Start with a more reasonable size.

	enc.writeByte(byte(tagsVersionID))
	for k, v := range m.m {
		enc.writeByte(byte(keyTypeString))
		enc.writeString(k.name)
		enc.writeString(v)
	}
	return enc.bytes()
}

// Decode  decodes the given []byte into a tag map.
func Decode(buf []byte) (*Map, error) {
	ts := newMap(0)
	if len(buf) == 0 {
		return ts, nil
	}

	d := &decoder{buf: buf}
	version := d.readByte()
	if version > tagsVersionID {
		return nil, fmt.Errorf("cannot decode: unsupported version: %q; supports only up to: %q", version, tagsVersionID)
	}

	for !d.ended() {
		typ := keyType(d.readByte())
		if typ != keyTypeString {
			return nil, fmt.Errorf("cannot decode: invalid key type: %q", typ)
		}

		k, err := d.readBytes()
		if err != nil {
			return nil, err
		}

		v, err := d.readBytes()
		if err != nil {
			return nil, err
		}

		key, err := NewKey(string(k))
		if err != nil {
			return nil, err // no partial failures
		}
		val := string(v)
		if !checkValue(val) {
			return nil, errInvalidValue // no partial failures
		}
		ts.upsert(key, val)
	}
	return ts, nil
}
