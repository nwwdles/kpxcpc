package client

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net"

	"golang.org/x/crypto/nacl/box"
)

var ErrFailedToOpen = errors.New("failed to open message")

type Client struct {
	log *log.Logger
	// Session
	conn         net.Conn
	privkey      [32]byte
	pubkey       [32]byte
	serverPubkey [32]byte
	clientID     [24]byte
	lastNonce    *[24]byte

	// Association
	idKey      [24]byte // client identifier key
	identifier string   // user-set identifier
}

func New(conn net.Conn, idKey *[24]byte, identifier string) (c *Client, err error) {
	pubkey, privkey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return
	}

	clientID, err := Nonce() // nonce has the same size as we want
	if err != nil {
		return
	}

	w := ioutil.Discard

	nonce, err := Nonce()
	if err != nil {
		return
	}

	c = &Client{
		log:       log.New(w, "", log.Lmicroseconds),
		conn:      conn,
		privkey:   *privkey,
		pubkey:    *pubkey,
		clientID:  *clientID,
		lastNonce: nonce,

		idKey:      *idKey,
		identifier: identifier,
	}

	return c, nil
}

func (c *Client) nonce() *[24]byte {
	c.lastNonce = incrementNonce(c.lastNonce)

	return c.lastNonce
}

func (c *Client) GetAssociation() (idKey [24]byte, identifier string) {
	return c.idKey, c.identifier
}

func (c *Client) makeRequest(request, response interface{}) (err error) {
	b, err := json.Marshal(request)
	if err != nil {
		return
	}

	if _, err = c.conn.Write(b); err != nil {
		return
	}

	buff := make([]byte, 1024)

	n, err := c.conn.Read(buff)
	if err != nil {
		return
	}

	c.log.Printf("\n\t-->Sent: %s\n\t<--Recv: %s\n", b, buff[:n])

	return json.Unmarshal(buff[:n], &response)
}

func (c *Client) makeRequestWithMessage(action string, message, response interface{}) (err error) {
	for {
		err = c.makeRequestWithMessageNoRetry(action, message, response)

		// TODO: find out why this is happening
		if errors.Is(err, ErrFailedToOpen) {
			continue
		}

		break
	}

	return
}

func (c *Client) makeRequestWithMessageNoRetry(action string, message, response interface{}) (err error) {
	nonce := c.nonce()

	msg, err := json.Marshal(message)
	if err != nil {
		return
	}

	c.log.Printf("-->MSG:\n%s\n", msg)

	req := Request{
		ClientID: c.clientID[:],
		Action:   action,
		Nonce:    Base64Bytes(nonce[:]),
		Message:  Base64Bytes(box.Seal([]byte{}, msg, nonce, &c.serverPubkey, &c.privkey)),
	}

	resp := &Response{}
	if err = c.makeRequest(req, resp); err != nil {
		return
	}

	if resp.Error != nil {
		return protocolError(*resp.Error, *resp.Code)
	}

	n := &[24]byte{}

	copy(n[:], resp.Nonce)

	c.lastNonce = n

	b, ok := box.Open([]byte{}, resp.Message, n, &c.serverPubkey, &c.privkey)
	if !ok {
		return ErrFailedToOpen
	}

	c.log.Printf("<--RECVMSG:\n%s\n", b)

	return json.Unmarshal(b, response)
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
