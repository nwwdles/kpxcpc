// The MIT License (MIT)
//
// Copyright (c) 2020 cupnoodles
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
//
package client

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
)

// Base64Bytes automatically converts an array of bytes to/from base64 string.
type Base64Bytes []byte

func (k *Base64Bytes) MarshalJSON() (out []byte, err error) {
	out = make([]byte, base64.StdEncoding.EncodedLen(len(*k)))
	base64.StdEncoding.Encode(out, *k)

	return json.Marshal(string(out))
}

func (k *Base64Bytes) UnmarshalText(data []byte) (err error) {
	*k = make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	_, err = base64.StdEncoding.Decode(*k, data)
	*k = bytes.Trim(*k, "\x00")

	return
}

func randomBytes(b []byte) (err error) {
	_, err = io.ReadFull(rand.Reader, b)
	return
}

func Nonce() (nonce *[24]byte, err error) {
	nonce = &[24]byte{}
	err = randomBytes(nonce[:])

	return
}

func incrementNonce(b *[24]byte) (out *[24]byte) {
	out = &[24]byte{}

	c := 1
	for i := range b {
		c += int(b[i])
		out[i] = byte(c) & 0xFF
		c >>= 8
	}

	return
}
