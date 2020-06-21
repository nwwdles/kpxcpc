package client

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
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

func makeRequest(conn io.ReadWriter, request, response interface{}) (err error) {
	b, err := json.Marshal(request)
	if err != nil {
		return
	}

	if _, err = conn.Write(b); err != nil {
		return
	}

	buff := make([]byte, 1024)

	n, err := conn.Read(buff)
	if err != nil {
		return
	}

	log.Printf("\n\t-->Sent: %s\n\t<--Recv: %s\n", b, buff[:n])

	return json.Unmarshal(buff[:n], &response)
}
