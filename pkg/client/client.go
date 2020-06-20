package client

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/cupnoodles14/kpxch-go/pkg/protocol"
	"golang.org/x/crypto/nacl/box"
)

type Client struct {
	conn         net.Conn
	privkey      *[32]byte
	pubkey       *[32]byte
	serverPubkey *[32]byte
	idKey        *[24]byte
	identifier   string
	dbID         *[24]byte
	clientID     string
}

func encode(b []byte) (s string) {
	return base64.StdEncoding.EncodeToString(b)
}

func decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func Nonce() (nonce *[24]byte, err error) {
	nonce = &[24]byte{}
	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return
	}

	return
}

func MakeRequest(conn io.ReadWriter, request, response interface{}) (err error) {
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

	log.Printf("\n\tSent: %s\n\tReceived: %s\n", b, buff[:n])

	return json.Unmarshal(buff[:n], &response)
}

func New() *Client {
	pubkey, privkey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	conn, err := net.Dial("unix", os.Getenv("XDG_RUNTIME_DIR")+"/kpxc_server")
	if err != nil {
		panic(err)
	}

	idKey, err := Nonce()
	if err != nil {
		panic(err)
	}

	return &Client{
		privkey:  privkey,
		pubkey:   pubkey,
		clientID: "golang",
		conn:     conn,
		idKey:    idKey,
	}
}

func (c *Client) encryptedRequest(action string, message, response interface{}) (err error) {
	nonce, err := Nonce()
	if err != nil {
		return
	}

	msg, err := json.Marshal(message)
	if err != nil {
		return
	}

	req := protocol.Request{
		Action:   action,
		Nonce:    encode(nonce[:]),
		ClientID: c.clientID,
		Message:  encode(box.Seal([]byte{}, msg, nonce, c.serverPubkey, c.privkey)),
	}

	resp := &protocol.Response{}
	if err = MakeRequest(c.conn, req, resp); err != nil {
		return
	}

	if resp.Error != nil {
		return errors.New(*resp.Error)
	}

	n := &[24]byte{}

	nx, err := decode(*resp.Nonce)
	if err != nil {
		return
	}

	copy(n[:], nx)

	msgb, err := decode(*resp.Message)
	if err != nil {
		return
	}

	b, ok := box.Open([]byte{}, msgb, n, c.serverPubkey, c.privkey)
	if !ok {
		return errors.New("failed to open message")
	}

	fmt.Println(string(b))

	return json.Unmarshal(b, response)
}
